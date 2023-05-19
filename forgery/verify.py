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

def verify(img,r,rows,cols,signature_length,sha_version,sig_technique,embed_technique):
    vk_bin=""
    if signature_length==1024:
        key_len=1032
    elif signature_length==2048:
        key_len=2056
    else:
        key_len=signature_length
    #timer for key extraction
    key_ex_start = time.time()
    for k in range(0,cols):
        pixel=img[r-1][k]
        for n in range(0,3):
            temp_str=str(format(pixel[n], '08b'))
            vk_bin+=temp_str[4:8]
            if len(vk_bin)==key_len:
                break
        if len(vk_bin)==key_len:
                break;
    key_ex_end = time.time()
    key_ex_time=(key_ex_end-key_ex_start)
    #timer for verifying key construction
    key_cons_start=time.time()
    if(sig_technique=="ECDSA"):
        m=key_len//4
        m='{0:0>'+str(m)+'x}'
        vk_hex_string=m.format(int(vk_bin, 2))
        # print (vk_hex_string,len(vk_hex_string))
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
    key_cons_end=time.time()
    key_cons_time=(key_cons_end-key_cons_start)
    
    #timer for verify signature
    sig_verify_start=time.time()
    for j in range(0,cols):
        s=""
     
        for i in range(r,rows):   
            # s+=str(base64.b64encode(img[i][j]))
            if(embed_technique=="FULL"):
                # count_pix_row=signature_length
                s+=str(format(img[i][j][0], '08b'))
                if len(s)==signature_length:
                    break
                s+=str(format(img[i][j][1], '08b'))
                if len(s)==signature_length:
                    break
                s+=str(format(img[i][j][2], '08b'))
                if len(s)==signature_length:
                    break

            elif(embed_technique=="LSB"):

                sig_pixel=list(img[i][j])

                for n1 in range(0,3):
                    temp=str(format(sig_pixel[n1], '08b'))
                    s+=temp[4:6]
                    if len(s)==key_len:
                        break
                    s+=temp[6:8]
                    if len(s)==key_len:
                        break
                if len(s)==key_len:
                    break     
        s1=""
        for p in range(0,r-1):
            s1+=str(base64.b64encode(img[p][j]))
        if sig_technique=="ECDSA":
            hex_string=m.format(int(s, 2))
            signature=bytes.fromhex(hex_string)
            if(sha_version=="sha256"):
                hash_bytes = hashlib.sha256(s1.encode('utf-8')).digest()
            elif(sha_version=="sha384"):
                hash_bytes = hashlib.sha384(s1.encode('utf-8')).digest()
            elif(sha_version=="sha512"):
                hash_bytes = hashlib.sha512(s1.encode('utf-8')).digest()
            s=""
            verifying_key.verify(signature, hash_bytes)
        else:
            m=signature_length//4
            m='{0:0>'+str(m)+'x}'
            hex_string=m.format(int(s, 2))
            signature=bytes.fromhex(hex_string)
            if sha_version=="sha256":
                hash_bytes = SHA256.new(bytes(s1.encode('utf-8')))            
            elif sha_version=="sha384":
                hash_bytes = SHA384.new(bytes(s1.encode('utf-8')))    
            elif sha_version=="sha512":
                hash_bytes = SHA512.new(bytes(s1.encode('utf-8')))
            verifying_key.verify(hash_bytes, signature)
    sig_verify_end=time.time()
    sig_verify_time=(sig_verify_end-sig_verify_start)
    return key_ex_time, key_cons_time, sig_verify_time

if __name__=='__main__':
    count=0
    verify_t=0
    sig_technique=sys.argv[1]
    sha_version=sys.argv[2]
    key_length=int(sys.argv[3])
    embed_technique=sys.argv[4]
    folder_dir='C:/Users/Dell/Desktop/IITD/sem4/mtp/forgery/'+sig_technique+"_"+sha_version+"_"+str(key_length)+"_"+embed_technique+"_"+"folder"
    os.chdir(folder_dir)
    #timers
    key_ex_time, key_cons_time, sig_verify_time=0,0,0
    for input_image in os.listdir(folder_dir):
        count+=1                                           
        # print (len(vk_bin))
        image=cv2.imread(input_image)                                     #image reading
        img=image.copy()
        image_name=os.path.splitext(input_image)[0]
        
        rows,cols=image.shape[:2]
        
        full_rows=0
        if(embed_technique=="FULL"):

            full_rows1=ceil(key_length/24)
            full_rows=full_rows1
     
        if(embed_technique=="LSB"):
            full_rows=ceil(key_length/12)
            #full_rows=full_rows1
        
        last_rows=rows-full_rows
        #print(last_rows,full_rows)
        
        # print (rows,cols,last_rows)
        a1, a2, a3=verify(img,last_rows,rows,cols,key_length,sha_version,sig_technique,embed_technique)
        key_ex_time+=a1
        key_cons_time+=a2
        sig_verify_time+=a3
        # filename = './embed/'+image_name+'embed'+'.jpg'
        # cv2.imwrite(filename, embedded_img) 
    print(f"Avg key extraction time of the program is {key_ex_time/count} sec")
    print(f"Avg verfying key construction time of the program is {key_cons_time/count} sec")
    print(f"Avg signature verification time of the program is {sig_verify_time/count} sec")
