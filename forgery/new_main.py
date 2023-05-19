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
import numpy as np

# SENDER

#signature calculation
def calculate_signature(algo,src,rows,cols,sk,key_len,sha_version,usefull_pixels,technique):
    sig=""  
    s=""
    if technique=="LSB":
        # print (usefull_pixels,rows,cols)
        i=rows-1
        j=0
        usefull_pixels_count=0
        while(i>=0):
            while(j<cols):
                if usefull_pixels_count==usefull_pixels:
                    break
                else:
                    s+=str(254 & (src[i][j][0]))
                    s+=str(254 & (src[i][j][1]))
                    s+=str(254 & (src[i][j][2]))
                    usefull_pixels_count+=1
                j+=1
            if usefull_pixels_count==usefull_pixels:
                break
            j=0
            i-=1
        # print (i,j)
        while(i>=0):
            while(j<cols):
                s+=str(base64.b64encode(src[i][j]))
                j+=1
            j=0
            i-=1
    else:
        i=0
        j=0
        while(i<rows-1):
            while(j<cols):
                s+=str(base64.b64encode(src[i][j]))
                j+=1
            j=0
            i+=1
    # print (s,len(s),"shiv")
    if algo=="ECDSA":
            #hash of string
        if sha_version=="sha256":
            # print (s)
            # hash_bytes = hashlib.sha256(s.encode('utf-8')).digest() 
            signature = (sk.sign(s.encode('utf-8'),hashfunc = hashlib.sha256)).hex()                        
        elif sha_version=="sha384":
            # hash_bytes = hashlib.sha384(s.encode('utf-8')).digest()     
            signature = (sk.sign(s.encode('utf-8'),hashfunc = hashlib.sha384)).hex()                   
        elif sha_version=="sha512":
            
            # hash_bytes = hashlib.sha512(s.encode('utf-8')).digest()
            signature = (sk.sign(s.encode('utf-8'),hashfunc = hashlib.sha512)).hex()
        # print (hash_bytes)
        # signature = sk.sign(hash_bytes).hex()                           #digital signature of column

        #digital signature of a row
        m='{0:0>'+str(key_len)+'b}'
        sig=m.format(int(signature, 16))
    else:
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
    #list of signatures
    # print (signature,hash_bytes,len(hash_bytes))
    return sig 

#4LSB embeddingy
def LSB_sig_embedding(img,sig,rows,cols,vk_bin,method_embedd):
    tt=method_embedd
    j=0
    i=0
    while(i<len(tt)):
        pixel_list=list(img[rows-1][j])
        for ln in range(3):
            pixel_list[ln] = (pixel_list[ln] & 254) | int(tt[i])
            i+=1
            if i==len(tt):
                break
        img[rows-1][j]=tuple(pixel_list)
        if i==len(tt):
                break
        j+=1
    # print (vk_bin,sig,len(vk_bin),len(sig))
    vk_bin+=sig
    # print (vk_bin,len(vk_bin))
    i=rows-1
    j=3
    itr=0
    while(i>=0):
        while(j<cols):
            pixel_list=list(img[i][j])
            for ln in range(0,3):
                pixel_list[ln] = (pixel_list[ln] & 254) | int(vk_bin[itr])
                itr+=1
                if itr==len(vk_bin):
                    break
            img[i][j]=tuple(pixel_list)
            if itr==len(vk_bin):
                    break
            j+=1
        if itr==len(vk_bin):
            break
        j=0
        i-=1
    return img

#FULL embedding
def FULL_sig_embedding(img,sig,rows,cols,vk_bin,key_len,method_embedd):

    # ls=method_embedd.split("_")
    # print(ls)
    tt=method_embedd
    #print(method_embedd,tt)
    j=0
    i=0
    
    while(i<len(tt)):
        pixel_list=list(img[rows-1][j])
        for ln in range(3):
            #pixel_list[ln]>>=1
            pixel_list[ln] = (pixel_list[ln] & 254) | int(tt[i])
            i+=1           
            if i==len(tt):
                break
        img[rows-1][j]=tuple(pixel_list)
        if i==len(tt):
                break

        j+=1
    j+=1
    c=0
    i=0
    
    last_rows=rows-1
    
    #key embedding
    m=int(key_len)//4
    m='{0:0>'+str(m)+'x}'
    vk_hex_string=m.format(int(vk_bin, 2))
    #print(vk_hex_string)
    while(i<len(vk_bin)):
        red_string=vk_bin[i:i+8]
        red_pixel=int(red_string,2)
        i+=8
        
        if i==len(vk_bin):
            green_pixel,blue_pixel=0,0
            img[last_rows][j]=(red_pixel,green_pixel,blue_pixel)
            break
        green_string=vk_bin[i:i+8]
        green_pixel=int(green_string,2)
        i+=8
        
        if i==len(vk_bin):
            blue_pixel=0
            img[last_rows][j]=(red_pixel,green_pixel,blue_pixel)
            break
        blue_string=vk_bin[i:i+8]
        blue_pixel=int(blue_string,2)
        i+=8
        # print (r1,x,rows,y)
        img[last_rows][j]=(red_pixel,green_pixel,blue_pixel)
        if i==len(vk_bin):
            break
        j+=1


    j+=1
    string=sig
    #print(sig)
    sig_len=len(string)
    i=0                 #cols number  
    
    while(i<len(string)):

    
        # pixel = list(img[x][y])
        red_string=string[i:i+8]
        red_pixel=int(red_string,2)
        i+=8
        
        if i==int(sig_len):
            green_pixel,blue_pixel=0,0
            img[last_rows][j]=(red_pixel,green_pixel,blue_pixel)
            break
        green_string=string[i:i+8]
        green_pixel=int(green_string,2)
        i+=8
        
        if i==int(sig_len):
            blue_pixel=0
            img[last_rows][j]=(red_pixel,green_pixel,blue_pixel)
            break
        blue_string=string[i:i+8]
        blue_pixel=int(blue_string,2)
        i+=8
        # print (r1,x,rows,y)
        img[last_rows][j]=(red_pixel,green_pixel,blue_pixel)
        if i==int(sig_len):
            break
        j+=1
    

    #print(j)
    return img



if __name__=='__main__':
    folder_dir=r'C:\Users\Dell\Desktop\IITD\sem4\mtp\forgery\input_imgs'
    os.chdir(folder_dir)
    vk_t,sig_t,embed_t=0,0,0
    count=0
    #command line arguments
    algo=sys.argv[1]
    
    sha_version=sys.argv[2]
    key_len=sys.argv[3]
    technique=sys.argv[4]

    
    if(algo=="RSA"):
        mpos1="01"
    else:
        mpos1="10"
    
    if(sha_version=="sha256"):
        mpos2="01"
    elif(sha_version=="sha384"):
        mpos2="10"
    else:
        mpos2="11"

    if(key_len=="256"):
        mpos3="01"
    elif(key_len=="320"):
        mpos3="10"
    elif(key_len=="384"):
        mpos3="11"
    elif(key_len=="1024"):
        mpos3="01"
    else:
        mpos3="10"
    
    if(technique=="FULL"):
        mpos4="01"
    else:
        mpos4="10"
    
    method_embedd=mpos1+mpos2+mpos3+mpos4
    
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
            # print (sk.to_string().hex(),len(sk.to_string().hex()), sk.verifying_key.to_string().hex())            
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
                RSA_Key_len="1032"
            else:
                signature_len="2056"
                RSA_Key_len="2056"
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
            dividing_num=3
        else:
            dividing_num=24
        # lsb_rows=ceil(len(vk_bin)/dividing_num)
        #calculate how many bits we want to use
        usefull_bits=len(vk_bin) + int(key_len)
        usefull_pixels=ceil(usefull_bits/dividing_num) + 3    #here 3 pixel for method
        # usefull_rows = ceil(usefull_pixels/cols)
        # last_rows=rows-usefull_rows
        # print(usefull_bits)
        # print (rows,cols,last_rows)

        #signature calculation timer
        #start
        sig_begin = time.time()
        sig=calculate_signature(algo,img,rows,cols,sk,key_len,sha_version,usefull_pixels,technique)               #signatue calculation
        #end timer
        sig_end = time.time()
        #print(sig_list)
        sig_t+=(sig_end-sig_begin)

        #embedding timer
        #start
        embed_begin = time.time()
        #embedding signature into image
        if technique=="LSB":
            embedded_img=LSB_sig_embedding(img,sig,rows,cols,vk_bin,method_embedd)   
        else:
            embedded_img=FULL_sig_embedding(img,sig,rows,cols,vk_bin,key_len,method_embedd)
        #end timer
        embed_end=time.time()
        embed_t+=(embed_end-embed_begin)

        #printing images
        cv2.imshow("orignal image",image)
        cv2.imshow("Embedding",image-embedded_img)
        cv2.imshow("Embedded image",embedded_img)
        cv2.waitKey(0)
        cv2.destroyAllWindows()
        folder_dir=r'C:\Users\Dell\Desktop\IITD\sem4\mtp\forgery'
        os.chdir(folder_dir)
        filename = './'+algo+"_"+sha_version+"_"+key_len+"_"+technique+"_"+"folder/"+image_name+'embedded'+'.png'
        cv2.imwrite(filename, embedded_img) 
        os.chdir(r'C:\Users\Dell\Desktop\IITD\sem4\mtp\forgery\input_imgs')
    print(f"Avg runtime for key generation is {(vk_t/count)*1000} millisec")
    print(f"Avg runtime for signature generation is {(sig_t/count)*1000} millisec")
    print(f"Avg runtime for signature embedding is {(embed_t/count)*1000} millisec")
    