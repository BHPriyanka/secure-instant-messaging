import sys, getopt, os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac

# This function will generate a symetric key for data encrytion.
def aeskeygen(shared_key):
   backend = default_backend()
   info = b"hkdf-example"
   hkdf = HKDFExpand(
      algorithm=hashes.SHA256(),
         length=32,
         info=info,
         backend=backend
   )
   key = hkdf.derive(shared_key)
   return key

# This function will generate a symetric key for data encrytion.
def keygen():
   backend = default_backend()
   salt = os.urandom(16)
   info = b"hkdf-example"
   hkdf = HKDF(
      algorithm=hashes.SHA256(),
         length=32,
         salt=salt,
         info=info,
         backend=backend
   )
   key = hkdf.derive(b"This is the symetric key!")
   return key

def RSADecrypt(msg, private_key):
   decrypted_msg = private_key.decrypt(
       msg,
       padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA1()),
         algorithm=hashes.SHA1(),
         label=None
    ))
   return decrypted_msg

def RSAEncrypt(msg, publickey):
 encrypted_msg = publickey.encrypt(
		   msg, 
		   padding.OAEP( 
			mgf=padding.MGF1(algorithm=hashes.SHA1()),
			algorithm=hashes.SHA1(),
			label=None
 ))
 return encrypted_msg

def AESDecrypt(sym_key, iv, msg):
 cipher = Cipher(algorithms.AES(sym_key), modes.OFB(iv), backend=default_backend())
 decryptor = cipher.decryptor()
 plaintext = decryptor.update(msg) + decryptor.finalize()
 return plaintext


def AESEncrypt(msg, aes_key, iv):
 #generate a aes key , iv and use it to encrypt the above msg
 cipher = Cipher(algorithms.AES(aes_key), modes.OFB(iv), backend=default_backend())
 encryptor = cipher.encryptor()
 ciphertext = encryptor.update(msg) + encryptor.finalize()
 return ciphertext

