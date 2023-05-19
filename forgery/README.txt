pip install pycryptodome

Running commands----
(1) Embedding-
		  key-length for RSA = 1024/2048
		  key-length for ECDSA = 256/320/384
		  
		----python main.py ECDSA/RSA sha256/sha384/sha512 key-length LSB/FULL
(2) Verifying-
		----python verify.py ECDSA/RSA sha256/sha384/sha512 key-length LSB/FULL