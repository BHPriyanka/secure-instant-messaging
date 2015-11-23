import os
import sys, getopt
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def main(argv):
   if len(argv) == 0:
      print '-g generate a key'
      print '-e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file'
      print '-d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file'
      sys.exit(2)
   try:
      opts, args = getopt.getopt(argv,"ged")
   except getopt.GetoptError:
      print '-g generate a key'
      print '-e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file'
      print '-d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file'
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-g':
         if len(args)!=0:
            print '-g generate a key'
            exit(2)
         # generate a private key
         rsaKeygen()
      elif opt =="-e":
         if len(args)!=4:
            print '-e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file'
            exit(2)
         # encrypt
         (destination_public_key_filename, sender_private_key_filename, input_plaintext_file, ciphertext_file) = args
         encrypt(destination_public_key_filename, sender_private_key_filename, input_plaintext_file, ciphertext_file)
      elif opt =="-d":
         if len(args)!=4:
            print '-d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file'
            exit(2)
         # decrypt
         (destination_private_key_filename, sender_public_key_filename, ciphertext_file, output_plaintext_file) = args
         decrypt(destination_private_key_filename, sender_public_key_filename, ciphertext_file, output_plaintext_file)

# This function will generate a RSA private-public key pair,
# Keys will be stored in the output files private_key and public_key
# respectively.
def rsaKeygen():
   private_key = rsa.generate_private_key(
       public_exponent=65537,
       key_size=2048,
       backend=default_backend()
   )
   pem = private_key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.TraditionalOpenSSL,
      encryption_algorithm=serialization.NoEncryption()
   )
   # write private key into file
   if os.path.isfile("./private_key"):
      os.remove("./private_key")
   f = open("./private_key", "wb")
   f.write(pem)
   f.close()

   # write public key into file
   public_key = private_key.public_key()
   pem = public_key.public_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo
   )
   if os.path.isfile("./public_key"):
      os.remove("./public_key")
   f = open("./public_key", "wb")
   f.write(pem)
   f.close()

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

# The encrypt function will takes in destination_public_key_filename, sender_private_key_filename, 
# input_plaintext_file, ciphertext_file as input argmuments. And encrypt the given plaintext with
# proper keys.
def encrypt(destination_public_key_filename, sender_private_key_filename, input_plaintext_file, ciphertext_file):
   # generate a symetric key
   key_sym = keygen();
   print 'key_sym len = ',len(key_sym)
   public_key = None
   private_key = None

   # encrypt key_sym with reciever's public key
   with open(destination_public_key_filename, "rb") as key_file:
      public_key = serialization.load_pem_public_key(
          key_file.read(),
          backend=default_backend()
      )
   cipher_key_sym = public_key.encrypt(
      key_sym,
      padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA1()),
         algorithm=hashes.SHA1(),
         label=None
      )
   )
   print 'cipher_key_sym len = ',len(bytes(cipher_key_sym))

   # encrypt file with key_sym
   iv = os.urandom(16)
   cipher = Cipher(algorithms.AES(key_sym), modes.OFB(iv), backend=default_backend())
   encryptor = cipher.encryptor()
   data = None
   with open(input_plaintext_file, "rb") as data_file:
      data = data_file.read()
      data_file.close()

   print 'data len = ',len(data)
   ciphertext = encryptor.update(data) + encryptor.finalize()
   print 'ciphertext len =',len(bytes(ciphertext))

   # sign the file with sender's private key
   with open(sender_private_key_filename, "rb") as key_file:
      private_key = serialization.load_pem_private_key(
         key_file.read(),
         password=None,
         backend=default_backend()
      )
   signer = private_key.signer(
       padding.PSS(
           mgf=padding.MGF1(hashes.SHA1()),
           salt_length=padding.PSS.MAX_LENGTH
       ),
       hashes.SHA1()
   )
   signer.update(bytes(ciphertext))
   signature = signer.finalize()
   print 'signature len = ',len(bytes(signature))

   # compose the cipher text: iv|key_sym|signature|file
   with open(ciphertext_file, "wb") as cipher_file:
      cipher_file.write(bytes(iv))
      cipher_file.write(bytes(cipher_key_sym))
      cipher_file.write(bytes(signature))
      cipher_file.write(bytes(ciphertext))
      cipher_file.close()

# The decrypt function will takes in destination_private_key_filename, sender_public_key_filename, 
# ciphertext_file, output_plaintext_file as input argmuments. And decrypt the given ciphertext with
# proper keys.
def decrypt(destination_private_key_filename, sender_public_key_filename, ciphertext_file, output_plaintext_file):
   cipher_key_sym = None
   signature = None
   ciphertext = None
   private_key = None
   public_key = None
   iv = None
   with open(ciphertext_file,'rb') as cipher_file:
      # the length of iv is 16
      # the length of encrypted key_sym is 256
      # the length of signature is 256
      iv = cipher_file.read(16)
      cipher_file.seek(16);
      cipher_key_sym = cipher_file.read(256)
      cipher_file.seek(16+256);
      signature = cipher_file.read(256)
      cipher_file.seek(16+256+256);
      ciphertext = cipher_file.read()
      cipher_file.close()

   with open(destination_private_key_filename, "rb") as key_file:
      private_key = serialization.load_pem_private_key(
         key_file.read(),
         password=None,
         backend=default_backend()
      )
   with open(sender_public_key_filename, "rb") as key_file:
      public_key = serialization.load_pem_public_key(
          key_file.read(),
          backend=default_backend()
      )

   # verify file signature
   verifier = public_key.verifier(
      signature,
      padding.PSS(
         mgf=padding.MGF1(hashes.SHA1()),
         salt_length=padding.PSS.MAX_LENGTH
      ),
      hashes.SHA1()
   )
   try:
      verifier.update(ciphertext)
      verifier.verify()
   except:
      print 'Verification failed!'
      exit(2)

   # decrypt key_sym with reciever's private key
   key_sym = private_key.decrypt(
      cipher_key_sym,
      padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA1()),
         algorithm=hashes.SHA1(),
         label=None
      )
   )

   # decrypt file with key_sym
   cipher = Cipher(algorithms.AES(key_sym), modes.OFB(iv), backend=default_backend())
   decryptor = cipher.decryptor()
   plaintext = decryptor.update(ciphertext) + decryptor.finalize()

   # compose the plain text
   with open(output_plaintext_file, "wb") as plaintext_file:
      plaintext_file.write(plaintext)
      plaintext_file.close()

if __name__ == "__main__":
   main(sys.argv[1:])