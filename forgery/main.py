import hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from ecdsa import SigningKey, VerifyingKey, BRAINPOOLP160r1,SECP128r1,NIST192p
from Crypto.Hash import SHA256, SHA384, SHA512
import cv2
import base64
import time,sys
import os
from os import listdir
from math import ceil

# SENDER

#signature calculation
def calculate_signature(algo,src,rows,cols,sk,key_len,sha_version):
    sig_list=[]  
    s=""
    if algo=="ECDSA":
        for j in range(0,cols):  
            for i in range(0,rows-1):   
                s+=str(base64.b64encode(src[i][j]))                         #string of column
            #hash of string
            if sha_version=="sha256":
                hash_bytes = hashlib.sha256(s.encode('utf-8')).digest()                         
            elif sha_version=="sha384":
                hash_bytes = hashlib.sha384(s.encode('utf-8')).digest()                        
            elif sha_version=="sha512":
                hash_bytes = hashlib.sha512(s.encode('utf-8')).digest()
            signature = sk.sign(hash_bytes).hex()                           #digital signature of column
        
            #digital signature of a row
            m='{0:0>'+str(key_len)+'b}'
            sig=m.format(int(signature, 16))
            sig_list.append(sig)
            s=""
    else:
        for j in range(0,cols):  
            for i in range(0,rows-1):   
                s+=str(base64.b64encode(src[i][j]))                         #string of column
            #hash of string
            if sha_version=="sha256":
                hash_bytes = SHA256.new(bytes(s.encode('utf-8')))            
            elif sha_version=="sha384":
                hash_bytes = SHA384.new(bytes(s.encode('utf-8')))    
            elif sha_version=="sha512":
                hash_bytes = SHA512.new(bytes(s.encode('utf-8')))
            signer = PKCS115_SigScheme(sk)
            signature = signer.sign(hash_bytes).hex()                       #digital signature of column
        
            #digital signature of a row
            m='{0:0>'+str(key_len)+'b}'
            sig=m.format(int(signature, 16))
            sig_list.append(sig)
            s=""
    #list of signatures
    return sig_list 

#4LSB embeddingy
def LSB_sig_embedding(img,sig,r,rows,cols,vk_bin,key_len):
    # print (r)
    # cv2.imshow("emd",img)
    vk_count=0
    for m in range(0,cols):
        vk_pixel=list(img[r-1][m])
        for n in range(0,3):
            #changing 4LSB of pixels
            vk_pixel[n]=vk_pixel[n]>>4
            half_string=str(format(vk_pixel[n], '04b'))
            half_string+=vk_bin[vk_count:vk_count+4]
            vk_pixel[n]=int(half_string,2)
            vk_count+=4
            if vk_count==len(vk_bin):
                break
        img[r-1][m]=tuple(vk_pixel)
        if vk_count==len(vk_bin):
            break
    #embedding signatures
    for y in range(0,cols):
        i=0
        string=sig[y]
        for x in range(r,rows):
            sig_pixel=list(img[x][y])
            for n1 in range(0,3):
                #changing 4LSB of pixels
                sig_pixel[n1]=sig_pixel[n1]>>4
                s1=str(format(sig_pixel[n1], '04b'))
                s1+=string[i:i+4]
                sig_pixel[n1]=int(s1,2)
                i+=4
                if i==len(string):
                    break
            img[x][y]=tuple(sig_pixel)
            if i==len(string):
                break
    return img

#FULL embedding
def FULL_sig_embedding(img,sig,r,rows,cols,vk_bin,key_len):
    # print (r)
    # cv2.imshow("emd",img)
    vk_count=0
    for m in range(0,cols):
        vk_pixel=list(img[r-1][m])
        for n in range(0,3):
            #changing 4LSB of pixels
            vk_pixel[n]=vk_pixel[n]>>4
            half_string=str(format(vk_pixel[n], '04b'))
            half_string+=vk_bin[vk_count:vk_count+4]
            vk_pixel[n]=int(half_string,2)
            vk_count+=4
            if vk_count==len(vk_bin):
                break
        img[r-1][m]=tuple(vk_pixel)
        if vk_count==len(vk_bin):
            break

    c=0
    for y in range(0,cols):
        i=0
        string=sig[y]
        for x in range(r,rows):
            # pixel = list(img[x][y])
            red_string=string[i:i+8]
            red_pixel=int(red_string,2)
            i+=8
            if i==int(key_len):
                green_pixel,blue_pixel=0,0
                img[x][y]=(red_pixel,green_pixel,blue_pixel)
                break
            green_string=string[i:i+8]
            green_pixel=int(green_string,2)
            i+=8
            if i==int(key_len):
                blue_pixel=0
                img[x][y]=(red_pixel,green_pixel,blue_pixel)
                break
            blue_string=string[i:i+8]
            blue_pixel=int(blue_string,2)
            i+=8
            # print (r1,x,rows,y)
            img[x][y]=(red_pixel,green_pixel,blue_pixel)
    return img


if __name__=='__main__':
    folder_dir='C:/Users/Dell/Desktop/IITD/sem4/mtp/forgery/input_imgs'
    os.chdir(folder_dir)
    vk_t,sig_t,embed_t=0,0,0
    count=0
    #command line arguments
    algo=sys.argv[1]
    sha_version=sys.argv[2]
    key_len=sys.argv[3]
    technique=sys.argv[4]
    #folder for embedded images
    folder_path = "../"+algo+"_"+sha_version+"_"+key_len+"_"+technique+"_"+"folder"
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    os.chdir(folder_dir)
    for input_image in os.listdir(folder_dir):
        count+=1
        # key pairs (key generation)
        image_name=os.path.splitext(input_image)[0]
        
        #key generation timer
        #start
        vk_begin = time.time()                                               #started the timer
        #private key
        if algo=="ECDSA":
            if key_len=="256":
                sk = SigningKey.generate(curve=SECP128r1)                         
            elif key_len=="320":
                sk = SigningKey.generate(curve=BRAINPOOLP160r1)                        
            elif key_len=="384":
                sk = SigningKey.generate(curve=NIST192p)                         
            verifying_key_hex_string = sk.verifying_key.to_string().hex()
            verifying_key=sk.verifying_key                                    #public key
            vk=verifying_key.to_string().hex()                                #PU key in hexadecimal
            # print (vk)
            #PU key in binary 
            m='{0:0>'+str(key_len)+'b}'
            vk_bin=m.format(int(vk, 16))
        else:
            sk = RSA.generate(bits=int(key_len))
            pubKey = sk.publickey()
            pn=pubKey.n
            signature_len=""
            if key_len=="1024":
                signature_len="1032"
            else:
                signature_len="2056"
            m='{0:0>'+str(signature_len)+'b}'
            vk_bin=m.format(pn)
        #end timer
        vk_end = time.time()
        vk_t+=(vk_end-vk_begin)
        # print (len(vk_bin))
        image=cv2.imread(input_image)                                     #image reading
        img=image.copy()
        rows,cols=image.shape[:2]
        dividing_num=0
        if technique=="LSB":
            dividing_num=12
        else:
            dividing_num=24
        lsb_rows=ceil(len(vk_bin)/dividing_num)
        last_rows=rows-lsb_rows
        # print (rows,cols,last_rows)

        #signature calculation timer
        #start
        sig_begin = time.time()
        sig_list=calculate_signature(algo,img,last_rows,cols,sk,key_len,sha_version)               #signatue calculation
        #end timer
        sig_end = time.time()
        sig_t+=(sig_end-sig_begin)

        #embedding timer
        #start
        embed_begin = time.time()
        #embedding signature into image
        if technique=="LSB":
            embedded_img=LSB_sig_embedding(img,sig_list,last_rows,rows,cols,vk_bin,key_len)   
        else:
            embedded_img=FULL_sig_embedding(img,sig_list,last_rows,rows,cols,vk_bin,key_len)
        #end timer
        embed_end=time.time()
        embed_t+=(embed_end-embed_begin)
        # cv2.imwrite("embedded_img_copy.png",embedded_img)
        # im =cv2.imread("embedded_img_copy.png")
        # retreived_sig_list=LSB_retrieval_Signatures(embedded_img,last_rows,rows,cols)
        # cv2.imshow("orig",image)
        # cv2.imshow("lsb",embedded_img)
        cv2.waitKey(0)
        cv2.destroyAllWindows()
        folder_dir='C:/Users/Dell/Desktop/IITD/sem4/mtp/forgery'
        os.chdir(folder_dir)
        filename = './'+algo+"_"+sha_version+"_"+key_len+"_"+technique+"_"+"folder/"+image_name+'embedded'+'.png'
        cv2.imwrite(filename, embedded_img) 
        os.chdir('C:/Users/Dell/Desktop/IITD/sem4/mtp/digi_sig/input_imgs')
    print(f"Avg runtime for key generation is {vk_t/count} sec")
    print(f"Avg runtime for signature generation is {sig_t/count} sec")
    print(f"Avg runtime for signature embedding is {embed_t/count} sec")
    