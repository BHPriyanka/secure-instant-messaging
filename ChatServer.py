import sys, getopt, os
import socket
import thread
import time
import base64
import hashlib, ctypes
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
from ChatClient import keygen

ClientList = []

def main(argv):
   commonPort = ''
   if len(argv) != 2:
      print 'ChatServer.py -p <commonPort>'
      sys.exit(2)
   try:
      opts, args = getopt.getopt(argv,"hp:")
   except getopt.GetoptError:
      print 'ChatServer.py -p <commonPort>'
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-h':
         print 'ChatServer.py -p <commonPort>'
         sys.exit()
      elif opt =="-p":
         commonPort = arg
   try:
      server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Use UDP for communication
      server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      server_socket.bind((socket.gethostname(), int(commonPort)))
      print 'Server Initialized at '+socket.gethostname()+':'+commonPort
   except:
      print 'error when init socket, exit...'
      sys.exit(2)
   while True:
      try:
         dataRecv, addr = server_socket.recvfrom(4096)
         print "received message length:", len(dataRecv)
         print "received addr:", addr
         (dynamic_socket, dynamic_port) = createDynamicPort()
         print "Dport = ",dynamic_port
         server_socket.sendto(str(dynamic_port), (addr[0], int(addr[1])))
         print "Dport sent to client"
         thread.start_new_thread(task,(dynamic_socket, addr, dataRecv))
      except socket.error:
         print 'socket error!'
         raise
         sys.exit(2)
      except:
         print 'error'
         raise
         continue

def createDynamicPort():
   Dsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Use UDP for communication
   Dsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
   Dsocket.bind((socket.gethostname(), 0))
   return (Dsocket, Dsocket.getsockname()[1])

def task(dynamic_socket, addr, dataRecv):
   # parse dataRecv: type|iv|key_sym|ciphertext
   msg_type = dataRecv[0]
   try:
      if msg_type == bytes(0x00):
         LoginSequence(dynamic_socket, addr, dataRecv)
      elif msg_type == bytes(0x01):
         msg = RSAdecrypt(dataRecv)
         (user, cipherCmd) = msg.split(',')
         cmd = DHdecrypt(cipherCmd)
         cmd_type = cmd.split(' ')[0]
         if cmd_type == 'list':
            ListSequence(user, cmd)
         elif cmd_type == 'send':
            FetchSequence(user, cmd)
         elif cmd_type == 'logout':
            LogoutSequence(user, cmd)
   except:
      print 'task error!'
      raise
   finally:
      dynamic_socket.close()


def LoginSequence(dynamic_socket, addr, dataRecv):
   #PDMSequence(clientInfo)
   # msg format greeting_msg = bytes(0x00)  + bytes(iv) + bytes(cipher_key_sym) + bytes(ciphertext)
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
   dynamic_socket.sendto(server_first_msg, (addr[0], int(addr[1])))
   exit()

   # ACK
   # waiting for the client send common port info and peer AuthKey
   # register those into eph-table
   pass

#def PDMSequence(clientInfo):
#   pass

def ListSequence(clientInfo):
   pass

def FetchSequence(clientInfo):
   pass

def LogoutSequence(clientInfo):
   pass

if __name__ == "__main__":
   main(sys.argv[1:])
