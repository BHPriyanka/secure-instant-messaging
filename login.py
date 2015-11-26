import os,sys,getopt,ctypes
import pickle
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac
from DHExample import DiffieHellman

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

def main(argv):
   username = ''
   password = ''
   if len(argv) !=4:
      print("login.py -u <username> -x <password>")
      sys.exit(2)
   try:
      opts, args = getopt.getopt(argv,"u:x:")
   except getopt.GetoptError:
      sys.exit(2)
   for opt, arg in opts:
      if opt =="-u":
         username = arg
      elif opt =="-x":
         password = arg

   
   #compute the nonce, a random no. of 32 bit
   nonce = os.urandom(32)

   W = hash(password) 
   
   u = DiffieHellman()

   #p = "{1}".format(u.prime.bit_length(), u.prime)
   p = str(u.prime)
   
   #a = "{1}".format(u.privateKey.bit_length(),u.privateKey)
   a = str(u.privateKey)

   #public key g^a mod p
   #dh_pub_key= "{1}".format(u.publicKey.bit_length(),u.publicKey)
   dh_pub_key = str(u.publicKey)
   
   #generate client rsa auth key pair
   try:
      sender_private_key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=2048,
      backend=default_backend())
   except:
      print("The provided backend does not implement RSABackend")


   #obtain the public key from the private key generated using RSA
   sender_public_key = sender_private_key.public_key()
   try:
      pem = sender_public_key.public_bytes(
           encoding=serialization.Encoding.PEM,
           format=serialization.PublicFormat.SubjectPublicKeyInfo)
   except:
      print("Serialization failed") 
 
   #get the server public key from the file
   try:
     with open('serverpubkey.pem', 'rb') as f1:
          serverpubkey = serialization.load_pem_public_key(f1.read(), backend=default_backend())
   except:
     print("The destination public key file is not present")
     sys.exit(2)  

 
   msg = username + ',' + str(nonce) + ',' + str(dh_pub_key) + ',' + str(pem)
   #print(msg)
  
  # encrypt using aes key 
   key_sym=keygen()
   iv = os.urandom(16)
   cipher = Cipher(algorithms.AES(key_sym), modes.OFB(iv), backend=default_backend())
   encryptor = cipher.encryptor()
   
   ciphertext = encryptor.update(str.encode(msg)) + encryptor.finalize()
   #print('ciphertext len =',len(bytes(ciphertext)))
   

   #encrypt the symmetric key with rsa public key
   cipher_key_sym = serverpubkey.encrypt(key_sym, padding.OAEP( mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))
   #print('cipher_key_sym len =',len(bytes(cipher_key_sym)))
   #print('iv len =',len(bytes(iv)))
   #print('greeting len =',len(bytes(0x00)))


   #constant for GREETING is 0x00

   greeting_msg = bytes(0x00)  + bytes(iv) + bytes(cipher_key_sym) + bytes(ciphertext)
   #print(greeting_msg)
  #cipher_file.write(bytes(iv))
  #cipher_file.write(bytes(cipher_key_sym))
  #cipher_file.write(bytes(ciphertext))
   
 
if __name__ == "__main__":
   main(sys.argv[1:])

