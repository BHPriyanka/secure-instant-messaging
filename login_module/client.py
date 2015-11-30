
import sys,getopt
import thread,socket,time
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

#Set the values of port and host to void
port=' '
host = ' '

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
    
##Check if there are enough command line arguments,if not prompt the user to enter all the arguments    
   if len(argv) < 2:
       print("Usage: lient.py -s <Server_IPaddress> -p <portnumber> -u <username> -x <password>")
       sys.exit(2) 


#Assign the user input of Port and Host to the variables
   try:
       opts, args = getopt.getopt(argv,"s:p:u:x")
   except getopt.GetoptError:
       sys.exit(2)
       
   for opt, arg in opts:
       if opt == "-p":
          port = arg
       elif opt =="-s":
           host = arg
       elif opt =="-u":
           username = arg
       elif opt =="-x":
           password = arg


    
#Open the socket with UDP protocol type.handle the exception if it fails by displaying appropriate error code
   try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
   except socket.error:
        print("Failed to create socket")
        sys.exit()

#Bind the client to the specified host and with port number as 0.Since there will be multiple clients,the server will allocate the port numbers randomly to the clients
   try:
         s.bind((host,0))
   except socket.error:
         print("Bind failed. Error Code: ")
         sys.exit()

   print("socket created, generating greeting msg")
#Send the GREETING message to the server indicating its first encounter with the server
   #compute the nonce, a random no. of 32 bit
   nonce = os.urandom(32)

   W = hash(password)
   u = DiffieHellman()

   p = str(u.prime)

   a = str(u.privateKey)

   #public key g^a mod p
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

   #encrypt using aes key
   key_sym=keygen()
   iv = os.urandom(16)
   cipher = Cipher(algorithms.AES(key_sym), modes.OFB(iv), backend=default_backend())
   encryptor = cipher.encryptor()

   ciphertext = encryptor.update(msg) + encryptor.finalize()

   #encrypt the symmetric key with rsa public key
   cipher_key_sym = serverpubkey.encrypt(key_sym, padding.OAEP( mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))

   #constant for GREETING is 0x00
   greeting_msg = bytes(0x00) + bytes(iv) + bytes(cipher_key_sym) + bytes(ciphertext)
   print("Sending greeting msg")
   s.sendto(greeting_msg,(host, int(port)))

#start the threads to send and receive messages to and from the server
   thread.start_new_thread(receive,(s,))
   thread.start_new_thread(SendMsg,(s,host,port))

   while 1:
        pass


#function to receive message from the server
def receive(s):
    while 1:
        try:
            d = s.recvfrom(1024)
            reply = d[0]
            addr = d[1]
	    print("=====================================================")
	    print(reply) 
	    print("=====================================================")

            #if reply == 'INCOMING':
                #print(reply)
            time.sleep(5)
        except socket.error:
            print("BroadCast error")
            sys.exit(2)
        except:
            continue

#function to send message to the server
def SendMsg(c,ip,port):
    while 1:
	
	MESSAGE="MESSAGE: " + raw_input()
        try:
            c.sendto(MESSAGE,(ip,int(port)))
        except socket.error:
            print("Send Error")
            sys.exit(2)
        time.sleep(5)


if __name__ == "__main__":
   main(sys.argv[1:])

