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


def extractmsg(serverprivkey, dataRecv):
  # bytes(0x01)  + bytes(iv) + bytes(cipher_key_sym) + bytes(ciphertext)
  cipher_key_sym = None
  ciphertext = None
  iv = None

  offset = 0
  msg_type = dataRecv[offset]
  offset += 1
  iv = dataRecv[offset:offset+16]
  offset += 16
  cipher_key_sym = dataRecv[offset:offset+256]
  offset += 256
  ciphertext = dataRecv[offset:len(dataRecv)]

 # decrypt cipher_key_new with reciever's private key
  new_key_sym = RSADecrypt(cipher_key_sym, serverprivkey)

 #decrypt the nwciphertext
  plaintext = AESDecrypt(new_key_sym, iv, ciphertext)
  nonce = bytes(plaintext)[0:32]
  s = str(plaintext[32:len(bytes(plaintext))])
  username = s.split(',')[0]
  cmd_cipher = plaintext[32+len(username)+1:len(bytes(plaintext))]
  return (iv, nonce, username, cmd_cipher)

def encryptSendMsg(destination_public_key, sender_private_key, input_plaintext):
   # generate a symetric key
   key_sym = keygen();
   public_key = None
   private_key = None

   # encrypt key_sym with reciever's public key
   public_key = destination_public_key

   cipher_key_sym = public_key.encrypt(
      key_sym,
      padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA1()),
         algorithm=hashes.SHA1(),
         label=None
      )
   )

   # encrypt file with key_sym
   iv = os.urandom(16)
   cipher = Cipher(algorithms.AES(key_sym), modes.OFB(iv), backend=default_backend())
   encryptor = cipher.encryptor()
   ciphertext = encryptor.update(input_plaintext) + encryptor.finalize()

   # sign the file with sender's private key
   private_key = sender_private_key
   signer = private_key.signer(
       padding.PSS(
           mgf=padding.MGF1(hashes.SHA1()),
           salt_length=padding.PSS.MAX_LENGTH
       ),
       hashes.SHA1()
   )
   signer.update(bytes(ciphertext))
   signature = signer.finalize()

   # compose the cipher text: iv|key_sym|signature|file
   return bytes(iv)+bytes(cipher_key_sym)+bytes(signature)+bytes(ciphertext)

# The decrypt function will takes in destination_private_key_filename, sender_public_key_filename, 
# ciphertext_file, output_plaintext_file as input argmuments. And decrypt the given ciphertext with
# proper keys.
def decryptSendMsg(dataRecv, destination_private, sender_public_key):
   cipher_key_sym = None
   signature = None
   ciphertext = None
   private_key = None
   public_key = None
   iv = None

   offset = 16
   iv = dataRecv[0:offset]
   cipher_key_sym = dataRecv[offset:offset+256]
   offset += 256
   signature = dataRecv[offset:offset+256]
   offset += 256
   ciphertext = dataRecv[offset:len(dataRecv)]

   private_key = destination_private

   public_key = sender_public_key

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
   return plaintext
