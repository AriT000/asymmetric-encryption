# asymmetric-encryption

An asymmetric encryption method that allows secure communication between two parties.  

Tools:
- Python
- Pycryptodome library
- https://cryptotools.net/rsagen - RSA key generator  



Example Usage: *(Alice sending message to Bob)*
1. `pip install pycryptodome` (install Pycryptodome library)  
2. `python3 sender.py message.txt bob_public.pem Transmitted_Data.txt`  
3. `python3 receiver.py Transmitted_Data.txt bob_private.pem decrypted.txt`


### How this works:
We first locally generate a public and private key pair for the sender and the receiver. Each party's key pair is generated using the CryptoTools.net RSA key generator. 

Then, in order for communication to go both ways, we created two general Python scripts:  

Sender: 
The sender script takes the message.txt file, encrypts the message with AES 256 and CBC mode, encrypts the AES key with the receiver’s RSA public key, computes the SHA-256 MAC, and saves the outputted text to Transmitted_Data.txt.

Receiver:
The receiver script takes the Transmitted_Data.txt file, decrypts the AES key with the receiver’s private key, validates the MAC, unpads the ciphertext, decrypts it and saves that output to decrypted.txt.
