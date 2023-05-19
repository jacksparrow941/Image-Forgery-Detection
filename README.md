# Image-Forgery-Detection
I have implemented image forgery detection system using Digital Signature Method. 
Used Different methods for Digital Signature Generation techniques ECDSA and RSA and also differenet embedding technique LSB, FULL. 

To run
for embedding/Processing
python new_main.py {"Digital Generation Method:"RSA/ECDSA} {"SHA variants":sha256/sha512/sha284} {"Key Length:" 256/320/384/1024/2048} {"Embedding Technique:"LSB/FULL}
example
python new_main.py RSA sha256 384 LSB

for verifying
python new_verify.py RSA sha256 384 LSB


