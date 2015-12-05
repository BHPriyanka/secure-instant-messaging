import sys, getopt
import socket
import thread
import time
import re
import base64, ctypes,os
from binascii import hexlify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac
from DHExample import DiffieHellman
from general_functions import aeskeygen, keygen, RSADecrypt, RSAEncrypt, AESDecrypt, AESEncrypt

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
dh_aes_key = None
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
   global client_socket

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
      # Common Port
      (client_socket, commonPort) = createDynamicPort()
      print 'Common Port at '+client_socket.getsockname()[0]+":"+str(client_socket.getsockname()[1])

      # start login sequence
      username = raw_input("user:")
      password = raw_input("password:")
      print username+":"+password
      LoginSequence(username, password)

      # passively listening on incomming conncetion from other clients.
      thread.start_new_thread(listenTask,(client_socket,))
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
	 ListSequence(username)
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

def LoginSequence(username, password):
   global server_socket
   global serverIP
   global serverPort
   global client_socket
   global commonPort
   global dh_aes_key
   global serverpubkey
   global Dport

   #compute the nonce, a random no. of 32 bit, W from password 
   nonce = os.urandom(32)
   W = hash(password)
   u = DiffieHellman()
   # modular prime and private key for DH exchange
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

   msg = str(nonce) + username + ',' + str(dh_pub_key) + ',' + str(pem)
  
   #encrypt using aes key
   key_sym=keygen()
   iv = os.urandom(16)
   ciphertext = AESEncrypt(msg, key_sym, iv)

   #encrypt the symmetric key with rsa public key
   cipher_key_sym = serverpubkey.encrypt(key_sym, padding.OAEP( mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))
   
   #constant for GREETING is 0x00
   greeting_msg = bytes(0x00)  + bytes(iv) + bytes(cipher_key_sym) + bytes(ciphertext)
   server_socket.sendto(greeting_msg, (serverIP, int(serverPort)))
   (Dport, addr) = server_socket.recvfrom(4096)
   print Dport
   (dataRecv, addr) = server_socket.recvfrom(4096)
   
   # use Dport to finish the rest of sequence server_socket.sendto(other_msg, (serverIP, Dport))
   # server_first_msg = bytes(0x00)  + bytes(iv) + bytes(cipher_key_sym) + bytes(ciphertext)
   # msg = nonce + dh_key_server + ',' + u.hashsecret
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

   # decrypt key_sym with sender's private key
   key_sym = RSADecrypt(cipher_key_sym, sender_private_key)

   # decrypt the ciphertext using the key_sym and iv
   plaintext = AESDecrypt(key_sym, iv, ciphertext)
   nonce = bytes(plaintext)[0:32]
   plaintext = str(bytes(plaintext[32:len(bytes(plaintext))]))

   #get data from plaintext
   split_data = plaintext.split(',')
   dh_key_server_public = split_data[0]
   hash_secret = split_data[1]

   #generate hash secret
   u.genHashSecret1(dh_key_server_public)
  
   try:
	if hash_secret == u.hashsecret1:
	  #generate DH shared key
	  u.genKey(dh_key_server_public)
	  server_socket.sendto(u.hashsecret1, (serverIP, int(Dport)))
   except:
	print('hash does not match' )
        sys.exit(2)

   print('Sending hash for verification')
   (dataRecv, addr) = server_socket.recvfrom(4096)
   offset = 0
   iv = dataRecv[offset:offset+16]
   offset += 16
   ciphertext = dataRecv[offset:len(dataRecv)]
   dh_aes_key = aeskeygen(u.key)
 
   #decrypt the ciphertext using the key_sym and iv
   plaintext = AESDecrypt(dh_aes_key, iv, ciphertext)
   msg = str(bytes(plaintext))
   print(hexlify(dh_aes_key))
   print('Recevied ACK')

   networkinfo = client_socket.getsockname()[0] + ',' + str(client_socket.getsockname()[1])

   # encrypt the network info using DH Key
   iv = os.urandom(16)
   nwinfo = AESEncrypt(networkinfo, dh_aes_key, iv)

   #encrypt username and encrypted networkinfo using new aes key , and encrypt sym key using rsa server ublic key
   new_iv = os.urandom(16)
   new_sym_key = keygen()
   msg_nwinfo = username + ',' + bytes(nwinfo)
   encrypted_msg = AESEncrypt(msg_nwinfo, new_sym_key, new_iv)

   #encrypt the symmetric key with rsa public key
   cipher_new_key = RSAEncrypt(new_sym_key, serverpubkey)

   info_msg = bytes(new_iv) + bytes(iv) + bytes(cipher_new_key) + bytes(encrypted_msg)
   print('Sending common port info and peer AuthKey')
   server_socket.sendto(info_msg, (serverIP, int(Dport)))  
   pass

def ListSequence(clientinfo):
   global dh_aes_key
   global serverpubkey
   global Dport
   global serverIP
   #format of list command {Alice,K{list}} server-public-key
   #encrypt the list command using the DH shared key
   iv = os.urandom(16)
   listinfo = AESEncrypt('list', dh_aes_key, iv)

   list_msg = clientinfo + ',' + bytes(listinfo)
   #encrypt username and list command using new aes key and then encrypt the aes key using server public key
   #new_iv = os.urandom(16)
   sym_key = keygen()
   encrypted_list = AESEncrypt(list_msg, sym_key, iv)

   cipher_sym_key = RSAEncrypt(sym_key, serverpubkey)
   send_list_msg = bytes(0x01) + bytes(iv) + bytes(cipher_sym_key) + bytes(encrypted_list)
   print('Sending list command')
   server_socket.sendto(send_list_msg, (serverIP, int(Dport)))
  
   #receive list of users active on the server 
   (dataRecv, addr) = server_socket.recvfrom(4096)
   offset = 0
   iv1 = dataRecv[offset:offset+16]
   offset += 16
   ciphernew = dataRecv[offset:len(dataRecv)]
   #decrypt ciphernew
   text = AESDecrypt(dh_aes_key, iv1, ciphernew)
   print str(bytes(text))

   pass

def LogoutSequence(clientInfo):
   global dh_aes_key
   global serverpubkey
   global Dport
   global serverIP

   #message format for logout {username,K{logout},N1}serverpublickey
   #encrypt the logout command using the DH shared key
   iv = os.urandom(16)
   logoutinfo = AESEncrypt('logout', dh_aes_key, iv)

   #compute the nonce
   N1 = os.urandom(32)
   print('N1: ', N1)
   exitinfo = bytes(N1) + ',' + bytes(username) + ',' + bytes(logoutinfo)

   #encrypt using aes key
   key_sym=keygen()
   #iv = os.urandom(16)
   ciphertext = AESEncrypt(exitinfo, key_sym, iv)

   #encrypt the symmetric key with rsa public key
   cipher_key_sym = serverpubkey.encrypt(key_sym, padding.OAEP( mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))

   exit_msg = bytes(0x01)  + bytes(iv) + bytes(cipher_key_sym) + bytes(ciphertext)
   server_socket.sendto(exit_msg, (serverIP, int(serverPort))) 
   pass

if __name__ == "__main__":
   main(sys.argv[1:])
