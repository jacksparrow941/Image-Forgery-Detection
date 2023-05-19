
from flask import Flask, render_template, request
import hashlib
from ecdsa import SigningKey, VerifyingKey, BRAINPOOLP160r1,SECP128r1, NIST192p
import cv2
from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256, SHA384, SHA512
import base64
import time,sys
import os
from os import listdir
from math import ceil
# from werkzeug import secure_filename
app = Flask(__name__)

@app.route('/')
def home():
    return render_template('user_login.html')

def verify(img,rows,cols):
    #methods extraction process begin
    #started timer for method extraction
    method_ex_start=time.time()
    jj=0
    mts=""
    while(len(mts)<8):
        sig_pixel=list(img[rows-1][jj])
        for n1 in range(0,3):
            mts+=str(sig_pixel[n1]&1)
            if len(mts)==8:
                break
        if len(mts)==8:
                break
        jj+=1
    jj+=1
    method_lst=[]
    for i in range(0,len(mts),2):
        temp=int(mts[i:i+2],2)
        method_lst.append(temp)
    #methods extraction process end
    
    #storing methods into variables
    if(method_lst[0]==1):
        sig_technique="RSA"
    else:
        sig_technique="ECDSA"

    if(method_lst[3]==1):
        embed_technique="FULL"
    else:
        embed_technique="LSB"

    if(method_lst[1]==1):
        sha_version="sha256"
    elif(method_lst[1]==2):
        sha_version="sha384"
    else:
        sha_version="sha512"
    if(sig_technique=="ECDSA"):
        if(method_lst[2]==1):
            signature_length=256
        elif(method_lst[2]==2):
           signature_length=320
        else:
            signature_length=384

    else:
        if(method_lst[2]==1):
            signature_length=1024
        else:
            signature_length=2048
    #methods are stored into variables now we can use them


    #defining key and signature lengths because in RSA key and signature lengths are different
    s1=""
    vk_bin=""
    sig = ""
    if signature_length==1024:
        key_len=1032
    elif signature_length==2048:
        key_len=2056
    else:
        key_len=signature_length
    #ended timer of methods extraction
    method_ex_end=time.time()
    method_ex_time=method_ex_end-method_ex_start

    #started timer for key and signature extraction
    key_sig_ex_start = time.time()
    # print (embed_technique)
    if embed_technique=="LSB":
        i=rows-1
        j=3
        sig_starting=0
        while(i>=0):
            while(j<cols):
                pixel_list=list(img[i][j])
                for ln in range(0,3):
                    if sig_starting==0:
                        vk_bin += str(pixel_list[ln] & 1)
                        if key_len==len(vk_bin):
                            sig_starting=1
                    else:
                        sig += str(pixel_list[ln] & 1)
                        if signature_length==len(sig):
                            break
                if signature_length==len(sig):
                        break
                j+=1
            if signature_length==len(sig):
                break
            j=0
            i-=1
    else:
        for k in range(jj,cols):
            
            pixel=img[rows-1][k]
            for n in range(0,3):
                temp_str=str(format(pixel[n], '08b'))
                vk_bin+=temp_str
                if len(vk_bin)==key_len:
                    break
            if len(vk_bin)==key_len:
                    break;
            jj+=1
        #sig extraction
        jj+=1
        ii=0
        i=rows-1
        sig_ext_st=time.time()
        while(ii<signature_length):
            sig+=str(format(img[i][jj][0], '08b'))
            ii+=8
            if len(sig)==signature_length:
                break
            sig+=str(format(img[i][jj][1], '08b'))
            ii+=8
            if len(sig)==signature_length:
                break
            sig+=str(format(img[i][jj][2], '08b'))
            #ii+=8
            if len(sig)==signature_length:
                break
            jj+=1  
        sig_ext_et=time.time()  
    #ended timer of key and signature extraction
    key_sig_ex_end = time.time()
    key_sig_ex_time=(key_sig_ex_end-key_sig_ex_start)


    #started timer for verifying key construction
    key_cons_start=time.time()
    if(sig_technique=="ECDSA"):
        m=key_len//4
        m='{0:0>'+str(m)+'x}'
        vk_hex_string=m.format(int(vk_bin, 2))
        #print (vk_hex_string,len(vk_hex_string))
        vk_byte_string=bytes.fromhex(vk_hex_string)
        if(key_len==320):
            verifying_key = VerifyingKey.from_string(vk_byte_string, curve= BRAINPOOLP160r1)
        if(key_len==384):
            verifying_key = VerifyingKey.from_string(vk_byte_string, curve= NIST192p)
        if(key_len==256):
            verifying_key = VerifyingKey.from_string(vk_byte_string, curve=SECP128r1 )
    else:
        pn=int(vk_bin,2)
        pe=65537
        pubK=RSA.construct((pn,pe),consistency_check=True)
        verifying_key = PKCS115_SigScheme(pubK)

    #ended timer for verifying key construction
    key_cons_end=time.time()
    key_cons_time=(key_cons_end-key_cons_start)
    

    
    #started process of hash bytes from whole image for verification
    #started timer for verify signature
    hash_gen_start=time.time()
    usefull_bits=signature_length + key_len
    usefull_pixels=ceil(usefull_bits/3) + 3    #here 3 pixel for method
    if embed_technique=="LSB":
        i=rows-1
        j=0
        usefull_pixels_count=0
        while(i>=0):
            while(j<cols):
                if usefull_pixels_count==usefull_pixels:
                    break
                else:
                    s1+=str(254 & (img[i][j][0]))
                    s1+=str(254 & (img[i][j][1]))
                    s1+=str(254 & (img[i][j][2]))
                    usefull_pixels_count+=1
                j+=1
            if usefull_pixels_count==usefull_pixels:
                break
            j=0
            i-=1
        # print (i,j)
        while(i>=0):
            while(j<cols):
                s1+=str(base64.b64encode(img[i][j]))
                j+=1
            j=0
            i-=1
    else:       
        s1=""
        for si in range(0,rows-1):
            for sj in range(0,cols):
                s1+=str(base64.b64encode(img[si][sj]))
    #ended timer of hash generation
    hash_gen_end=time.time()
    hash_gen_time=hash_gen_end-hash_gen_start

    #started process of verification
    #$started timer of verification
    sig_verify_start=time.time()
    if sig_technique=="ECDSA":
        hex_string=m.format(int(sig, 2))
        signature=bytes.fromhex(hex_string)
        if(sha_version=="sha256"):
            # hash_bytes = hashlib.sha256(s1.encode('utf-8')).digest()
            verifying_key.verify(signature, s1.encode('utf-8'), hashlib.sha256)
        elif(sha_version=="sha384"):
            # hash_bytes = hashlib.sha384(s1.encode('utf-8')).digest()
            verifying_key.verify(signature, s1.encode('utf-8'), hashlib.sha384)
        elif(sha_version=="sha512"):
            # hash_bytes = hashlib.sha512(s1.encode('utf-8')).digest()
            verifying_key.verify(signature, s1.encode('utf-8'), hashlib.sha512)
        # verifying_key.verify(signature, hash_bytes)
    else:
        m=signature_length//4
        m='{0:0>'+str(m)+'x}'
        hex_string=m.format(int(sig, 2))
        signature=bytes.fromhex(hex_string)
        if sha_version=="sha256":
            hash_bytes = SHA256.new(bytes(s1.encode('utf-8')))            
        elif sha_version=="sha384":
            hash_bytes = SHA384.new(bytes(s1.encode('utf-8')))    
        elif sha_version=="sha512":
            hash_bytes = SHA512.new(bytes(s1.encode('utf-8')))
        # print (signature,hash_bytes)
        verifying_key.verify(hash_bytes, signature)
    #ended timer of verification
    sig_verify_end=time.time()
    sig_verify_time=(sig_verify_end-sig_verify_start)
    # return method_ex_time,key_sig_ex_time, key_cons_time, hash_gen_time,sig_verify_time
    return "Image is Genuine"

@app.route('/', methods = ['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['image']
        print (file)
        file.save(file.filename)
        img= cv2.imread(file.filename)
        rows,cols=img.shape[:2]
        res=""
        try:
            res = verify(img,rows,cols)
        except:
            res="FAKE"
        # cv2.imshow("img",file)
        # cv2.waitKey(0)
        # cv2.destroyAllWindows()
        # image_url = 'C:/Users/Nutan singh/Desktop/web'
        if res=="Image is Genuine":
            return render_template('true.html')
        return render_template('false.html')
       
        # return f'Image {file.filename} uploaded and displayed:<br><img src="url_for(file.filename)">'

    return render_template('1st.html',image=file)
	

if __name__ == '__main__':
    app.run(debug=True)

