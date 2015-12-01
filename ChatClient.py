import sys, getopt
import socket
import thread
import time
import re
import base64, ctypes,os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac
from DHExample import DiffieHellman

# local
server_socket = None
serverCommPort = None
client_socket = None
commonPort = None
username = None
password = None
# remote
serverIP = None
serverPort = None

def hash32(value):
   # use this to calculate W from password string.
   return hash(value) & 0xffffffff

def main(argv):
   global server_socket
   global serverCommPort
   global client_socket
   global commonPort
   global serverIP
   global serverPort

   if len(argv) != 4:
      print 'ChatClient.py -s <serverIP> -p <serverPort>'
      sys.exit(2)
   try:
      opts, args = getopt.getopt(argv,"hs:p:")
   except getopt.GetoptError:
      print 'ChatClient.py -s <serverIP> -p <serverPort>'
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-h':
         print 'ChatClient.py -s <serverIP> -p <serverPort>'
         sys.exit()
      elif opt =="-s":
         serverIP = arg
      elif opt =="-p":
         serverPort = arg

   try:
      # Server Communication Port
      (server_socket,serverCommPort) = createDynamicPort()
      print 'Server Communication Port at '+server_socket.getsockname()[0]+":"+str(server_socket.getsockname()[1])
      # start login sequence
      username = raw_input("user:")
      password = raw_input("password:")
      print username+":"+password
      LoginSequence(username, password)

      # Common Port
      (client_socket, commonPort) = createDynamicPort()
      print 'Common Port at '+client_socket.getsockname()[0]+":"+str(client_socket.getsockname()[1])
      # passively listening on incomming conncetion from other clients.
      thread.start_new_thread(listenTask,(client_socket))
   except :
      print 'error when init socket, exit...'
      raise
      sys.exit(2)
   while True:
      # Cmd Task:
      # send username msg
      # list
      # block main thread until sequence finished
      inputStr = raw_input()
      cmdComponents = re.split('\W+', inputStr)
      if cmdComponents[0] == 'list':
         # list sequence
         print 'list sequence'
      elif cmdComponents[0] == 'send':
         if len(cmdComponents)<3:
            print 'send <user> <message>'
            continue
         user = cmdComponents[1]
         msg = ' '.join(cmdComponents[2:len(cmdComponents)])
         print 'send sequence'
         print 'msg:' + msg
         MsgSendSequence(user, msg)
      elif cmdComponents[0] == 'exit':
         print 'logout sequence'
         LogoutSequence(username)
         exit(0)

def createDynamicPort():
   Dsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Use UDP for communication
   Dsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
   Dsocket.bind((socket.gethostname(), 0))
   return (Dsocket, Dsocket.getsockname()[1])


def listenTask(client_socket):
   while True:
      try:
         (dataRecv, addr) = client_socket.recvfrom(4096)
         print "received message length:", len(dataRecv)
         print "received addr:", addr
         (dynamic_socket, dynamic_port) = createDynamicPort()
         client_socket.sendto(dynamic_port, (addr[0], addr[1]))
         thread.start_new_thread(MsgRecvSequence,(dynamic_socket, addr, dataRecv))
      except socket.error:
         print 'listenTask socket error!'
         sys.exit(2)
      except:
         continue

def AuthSequenceA(peerInfo):
   # sending GREETING to another client
   # waitng to receive portInfo
   # use this port info to finish authentication
   # generate CommKey and send to peer
   pass

def AuthSequenceB(dynamic_socket, peerAdd, init_msg):
   global server_socket
   # decrypt peer's user name
   (peername, r2) = RSAdecrypt(init_msg)
   # fetch peer's AuthKey
   cmd = "send "+peername+" _"
   cipherCmd = DHencrypt(cmd)
   msg = username + ',' + cipherCmd
   cipherMsg = RSAencrypt(msg)
   server_socket.sendto(cipherMsg,(serverIP, int(serverPort)))
   (dataRecv, addr) = server_socket.recvfrom(4096)
   print "received message length:", len(dataRecv)
   print "received addr:", addr
   msg = DHdecrypt(dataRecv)
   # msg = peerIP, peerCommonPort, PeerRSAAuth
   peerRSAKey = msg.split(',')[2]
   # finish the authentication
   r1 = os.urandom(16)
   r1_e = RSAencrypt(r1, peerRSAKey)
   msg = bytes(r2)+bytes(r1_e)
   dynamic_socket.sendto(msg, (peerAdd[0], int(peerAdd[1])))
   # waiting for CommKey
   (dataRecv, addr) = dynamic_socket.recvfrom(4096)
   r1_r = dataRecv[0:16]
   if r1_r!=r1:
      print 'verificatoin failed'
      return
   peerRSACommKey = dataRecv[16:len(dataRecv)]
   # generate CommKey and send to peer
   (RSACommKey_Prv, RSACommKey_Pub) = RSAKeyGen()
   msg = RSAencrypt(RSACommKey_Pub, peerRSACommKey)
   dynamic_socket.sendto(msg, (peerAdd[0], int(peerAdd[1])))
   return (RSACommKey_Prv, peerRSACommKey)

def MsgSendSequence(user, msg):
   # fetch user info from server
   peerInfo=''
   AuthSequenceA(peerInfo)
   # encrypt msg and send it to peer

def MsgRecvSequence(dynamic_socket, peerAdd, dataRecv):
   (RSACommKey_Prv, peerRSACommKey) = AuthSequenceB(dynamic_socket, peerAdd, dataRecv)
   # decrypt msg and output it on console

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

def LoginSequence(username, password):
   global server_socket
   global serverIP
   global serverPort
   # PDMSequence(username, password)
    #compute the nonce, a random no. of 32 bit
   nonce = os.urandom(32)

   W = hash(password)
   #print(W)
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
   #print(pem)
  # encrypt using aes key
   key_sym=keygen()
   #print(key_sym)
   iv = os.urandom(16)
   cipher = Cipher(algorithms.AES(key_sym), modes.OFB(iv), backend=default_backend())
   encryptor = cipher.encryptor()

   ciphertext = encryptor.update(msg) + encryptor.finalize()
   #print('ciphertext len =',len(bytes(ciphertext)))


   #encrypt the symmetric key with rsa public key
   cipher_key_sym = serverpubkey.encrypt(key_sym, padding.OAEP( mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))
   #print('cipher_key_sym len =',len(bytes(cipher_key_sym)))
   #print('iv len =',len(bytes(iv)))
   #print('greeting len =',len(bytes(0x00)))


   #constant for GREETING is 0x00

   greeting_msg = bytes(0x00)  + bytes(iv) + bytes(cipher_key_sym) + bytes(ciphertext)

   server_socket.sendto(greeting_msg, (serverIP, int(serverPort)))
   (Dport, addr) = server_socket.recvfrom(4096)
   print Dport
   (dataRecv, addr) = server_socket.recvfrom(4096)
   print dataRecv
   # use Dport to finish the rest of sequence server_socket.sendto(other_msg, (serverIP, Dport))
   exit()

   # waiting for ACK
   # send common port info and peer AuthKey

   pass

#def PDMSequence(username, password):
#   pass

def FetchSequence(clientInfo):
   pass

def LogoutSequence(clientInfo):
   pass

if __name__ == "__main__":
   main(sys.argv[1:])
