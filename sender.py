import sys, base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256

# define a padding block size
block = AES.block_size

# padding function that fills out the last block to full length
def pad(data: bytes):
    # find number of padding bytes needed
    pad_length = block - (len(data) % block)
    # add and return pad bytes to the data
    return data + bytes([pad_length]) * pad_length

# function to load rsa key
def load_public(path):
    with open(path, "rb") as file:
        return RSA.import_key(file.read())

# main function
def main():
    # example command:
    # "python3 sender.py message.txt bob_public.pem transmitted_data.txt"
    message, receiver_public, output = sys.argv[1:4]

    # open the message
    text = open(message, "rb").read()
    # encrypt the message with AES 256 and CBC mode
    aes_key = get_random_bytes(32)
    nonce = get_random_bytes(block)
    cipher = AES.new(aes_key, AES.MODE_CBC, nonce)
    # the completed ciphertext with AES and the nonce
    ciphertext = cipher.encrypt(pad(text))

    # now encrypt the AES key with the receiver's RSA public key
    rsa_cipher = PKCS1_OAEP.new(load_public(receiver_public))
    encrypted_key = rsa_cipher.encrypt(aes_key)

    # now do SHA256
    hash_mac = HMAC.new(aes_key, digestmod=SHA256)
    hash_mac.update(nonce + ciphertext)
    mac = hash_mac.digest()

    # save the text to Transmitted_Data
    with open(output, "w") as file:
        for blob in (encrypted_key, nonce, ciphertext, mac):
            file.write(base64.b64encode(blob).decode() + "\n")
    
if __name__ == "__main__":
    main()
    print("\nMessage sent!\n")