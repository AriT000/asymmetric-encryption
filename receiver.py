import sys, base64
from Crypto.Cipher    import AES, PKCS1_OAEP
from Crypto.Hash      import HMAC, SHA256
from Crypto.PublicKey import RSA

# define a padding block size
block = AES.block_size

# function that reverses the padding from the data
def unpad(data: bytes):
    # find length of padding bytes
    pad_lenth = data[-1]
    # will return data without padding
    return data[:-pad_lenth]

# function to load rsa key
def load_private(path):
    with open(path, "rb") as file:
        return RSA.import_key(file.read())

# Main function
def main():
    # example command:
    # "python3 sender.py message.txt bob_public.pem transmitted_data.txt"
    input_txt, receiver_private, output = sys.argv[1:4]

    # open Transmitted_data
    with open(input_txt, "r") as f:
        enc_key_b64 = f.readline().strip()
        nonce_b64      = f.readline().strip()
        ct_b64      = f.readline().strip()
        mac_b64     = f.readline().strip()
    
    # decode base64
    enc_key   = base64.b64decode(enc_key_b64)
    nonce        = base64.b64decode(nonce_b64)
    ciphertext= base64.b64decode(ct_b64)
    mac       = base64.b64decode(mac_b64)

    # now decrypt AES key with receiever's private key
    rsa_cipher   = PKCS1_OAEP.new(load_private(receiver_private))
    decrypted_key    = rsa_cipher.decrypt(enc_key)

    # validate the mac
    hash_mac = HMAC.new(decrypted_key, digestmod=SHA256)
    hash_mac.update(nonce + ciphertext)
    hash_mac.verify(mac)

    # unpad the ciphertext and decrypt it
    cipher = AES.new(decrypted_key, AES.MODE_CBC, nonce)
    # the completed decrypted text
    text = unpad(cipher.decrypt(ciphertext))

    # save the decrypted text 
    with open(output, "wb") as file:
        file.write(text)

if __name__ == "__main__":
    main()
    print("\nMessage received!\n")