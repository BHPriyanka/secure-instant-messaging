import os,sys,getopt,ctypes
import pickle
import base64
import hashlib
from binascii import hexlify 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac
from DHExample import DiffieHellman
from login import keygen

def main():

# msg format greeting_msg = bytes(0x00)  + bytes(iv) + bytes(cipher_key_sym) + bytes(ciphertext)
 try:
     with open('login_ouput.txt', 'rb') as f:
          msg = f.read()
 except:
     print("The file specified does not exist")
     sys.exit(2)
 cipher_key_sym = None
 ciphertext = None
 iv = None

 offset = 0
 msg_type = msg[offset]
 offset += 1
 iv = msg[offset:offset+16]
 offset += 16
 cipher_key_sym = msg[offset:offset+256]
 offset += 256
 ciphertext = msg[offset:len(msg)]

 try:
     with open('serverprivkey.pem', 'rb') as f:
          serverprivkey = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
 except:
     print("The file specified does not exist")
     sys.exit(2)

 # decrypt key_sym with reciever's private key
 key_sym = serverprivkey.decrypt(
     cipher_key_sym,
     padding.OAEP(
       mgf=padding.MGF1(algorithm=hashes.SHA1()),
       algorithm=hashes.SHA1(),
       label=None
  ))
 

 #decrypt the ciphertext using the key_sym and iv
 cipher = Cipher(algorithms.AES(key_sym), modes.OFB(iv), backend=default_backend())
 decryptor = cipher.decryptor()
 plaintext = decryptor.update(ciphertext) + decryptor.finalize()

 #get data from plaintext
 split_data = plaintext.split(',')

 username = split_data[0]
 nonce = split_data[1]
 #2^a mod p
 client_dh_pub_key = split_data[2]
 client_rsa_pub_key = split_data[3]
 #print(client_rsa_pub_key)
 client_rsa_auth_key =  serialization.load_pem_public_key(client_rsa_pub_key, backend=default_backend())
 #print(split_data[3])
 #print(username)
 #print(nonce)
 #print(client_dh_pub_key)
 #W = hash('chuty')
 #print(W)
 #calculate 2^b mod p
 u = DiffieHellman()
 b = str(u.privateKey)
 dh_key_server = str(u.publicKey)
 p = str(u.prime)

 u.genHashSecret(client_dh_pub_key)

 #print("Key:", hexlify(u.key))
 #print(hexlify(u.hashsecret))
 
 msg = nonce + ',' + dh_key_server + ',' + u.hashsecret
 
 #generate a aes key , iv and use it to encrypt the above msg
 aes_key = keygen()
 iv = os.urandom(16)
 cipher = Cipher(algorithms.AES(aes_key), modes.OFB(iv), backend=default_backend())
 encryptor = cipher.encryptor()

 ciphertext = encryptor.update(msg) + encryptor.finalize()
 #encrypt the symmetric key with client's rsa public key
 cipher_key_sym = client_rsa_auth_key.encrypt(aes_key, padding.OAEP( mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))

 #constant for GREETING is 0x00
 server_first_msg = bytes(0x00)  + bytes(iv) + bytes(cipher_key_sym) + bytes(ciphertext)
 f = open('server_first_msg.txt','wb')
 f.write(server_first_msg)
 f.close()



if __name__ == "__main__":
   main()

