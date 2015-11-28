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
 
 #print(key_sym)

 #decrypt the ciphertext using the key_sym and iv
 cipher = Cipher(algorithms.AES(key_sym), modes.OFB(iv), backend=default_backend())
 decryptor = cipher.decryptor()
 plaintext = decryptor.update(ciphertext) + decryptor.finalize()
 #print(plaintext)

 #get data from plaintext
 split_data = plaintext.split(',')

 username = split_data[0]
 nonce = split_data[1]
 #2^a mod p
 client_dh_pub_key = split_data[2]
 client_rsa_pub_key = split_data[3]
 print(client_rsa_pub_key)
 client_rsa_auth_key =  serialization.load_pem_public_key(client_rsa_pub_key, backend=default_backend())
 #print(split_data[3])
 #print(username)
 #print(nonce)
 #print(client_dh_pub_key)
 W = hash('chuty')
 #print(W)
 #calculate 2^b mod p
 u = DiffieHellman()
 b = str(u.privateKey)
 dh_key_server = str(u.publicKey)
 p = str(u.prime)

 #calculate the DH key hash(2^ab mod p,2^bW mod p
# def genKey(otherKey):
#	 """
#	 Derive the shared secret, then hash it to obtain the shared key.
#	 """
#	 sharedSecret = u.genSecret(u.privateKey, int(otherKey))
#	 #sharedWSecret = u.genSecret(W, u.publicKey)
#	 # Convert the shared secret (int) to an array of bytes in network order
#	 # Otherwise hashlib can't hash it.
#	 try:
#	    _sharedSecretBytes = sharedSecret.to_bytes(
#	    sharedSecret.bit_length() // 8 + 1, byteorder="big")
#	  #  _sharedWSecretBytes = sharedWSecret.to_bytes(
#	  #  sharedWSecret.bit_length() // 8 + 1, byteorder="big")
#
#	 except AttributeError:
#	    _sharedSecretBytes = str(sharedSecret) 
#	    s = hashlib.sha256()
#	    s.update(bytes(_sharedSecretBytes))
#	    key = s.digest()
#	 return key
# def getKey():
 #	return key

 u.genKey(client_dh_pub_key)

# hashed_secret_key = genKey(client_dh_pub_key)
# print(u.genKey(client_dh_pub_key))
# print(u.genSecret(client_dh_pub_key))
 print("Key:", hexlify(u.key))

if __name__ == "__main__":
   main()

