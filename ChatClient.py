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
from general_functions import encryptSendMsg, decryptSendMsg

# local
server_socket = None
serverCommPort = None
client_socket = None
commonPort = None
username = None
password = None
sender_private_key = None
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
   global username
   global password

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
      client_socket.settimeout(None)
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
      sys.exit(2)
   while True:
      # Cmd Task:
      # send username msg
      # list
      # block main thread until sequence finished
      inputStr = raw_input()
      cmdComponents = re.split('\s+', inputStr)
      if cmdComponents[0] == 'list':
         print 'list sequence'
         ListSequence(username)
      elif cmdComponents[0] == 'send':
         if len(cmdComponents)<3:
            print 'send <user> <message>'
            continue
         user = cmdComponents[1]
         msg = ' '.join(cmdComponents[2:len(cmdComponents)])
         MsgSendSequence(user, msg)
      elif cmdComponents[0] == 'logout':
         LogoutSequence(username)
         

def createDynamicPort():
   Dsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Use UDP for communication
   # Dsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
   Dsocket.bind((socket.gethostname(), 0))
   # every socket will timeout in 5 seconds!
   Dsocket.settimeout(20)
   return (Dsocket, Dsocket.getsockname()[1])


def listenTask(client_socket):
   print "listening on "+client_socket.getsockname()[0]+":"+str(client_socket.getsockname()[1])
   while True:
      try:
         (dataRecv, addr) = client_socket.recvfrom(4096)
         print "received message length:", len(dataRecv)
         print "received addr:", addr
         (dynamic_socket, dynamic_port) = createDynamicPort()
         client_socket.sendto(str(dynamic_port), (addr[0], addr[1]))
         thread.start_new_thread(MsgRecvSequence,(dynamic_socket, addr, dataRecv))
      except socket.error:
         print 'listenTask socket error!'
         sys.exit(2)
      except:
         print "Unexpected error:", sys.exc_info()[0]
         continue

def AuthSequenceA(peerInfo):
   global username
   global sender_private_key
   peer_ip = peerInfo.split(',')[0]
   peer_port = peerInfo.split(',')[1]
   peer_authKey = peerInfo.split(',')[2]
   # sending GREETING to another client
   (dynamic_socket, dynamic_port) = createDynamicPort()
   print "createDynamicPort For peer auth: "+str(dynamic_port)
   peer_authKey =  serialization.load_pem_public_key(peer_authKey, backend=default_backend())
   r2 = os.urandom(32)
   greeting_msg = bytes(r2)+bytes(username)
   greeting_msg = RSAEncrypt(greeting_msg, peer_authKey)
   print "len(greeting_msg) = "+str(len(greeting_msg))
   print "peer_ip = "+peer_ip
   print "peer_port = "+peer_port

   dynamic_socket.sendto(greeting_msg,(peer_ip,int(peer_port)))
   # waitng to receive portInfo
   (Dport, addr) = dynamic_socket.recvfrom(4096)
   print "Dport = "+Dport
   (dataRecv, addr) = dynamic_socket.recvfrom(4096)
   # use this port info to finish authentication
   r2_d = dataRecv[0:32]
   if r2_d != r2:
      print "R2 verification failed!"
      dynamic_socket.close()
      return None
   r1_e = dataRecv[32:len(dataRecv)]
   r1 = RSADecrypt(r1_e, sender_private_key)
   # generate CommKey and send to peer
   try:
      comm_private_key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=2048,
      backend=default_backend())
   except:
      print("The provided backend does not implement RSABackend")
      return None

   #obtain the public key from the private key generated using RSA
   comm_public_key = comm_private_key.public_key()
   try:
      pem = comm_public_key.public_bytes(
           encoding=serialization.Encoding.PEM,
           format=serialization.PublicFormat.SubjectPublicKeyInfo)
      pem_s = comm_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
   )
   except:
      print("Serialization failed")
      return None

   pem_cipher = encryptSendMsg(peer_authKey, sender_private_key, pem)
   msg = bytes(r1)+bytes(pem_cipher)
   dynamic_socket.sendto(msg,(peer_ip, int(Dport)))
   (peerCommKey, addr) = dynamic_socket.recvfrom(4096)
   peerCommKey = decryptSendMsg(peerCommKey, sender_private_key, peer_authKey)
   return (peerCommKey, pem_s, dynamic_socket, addr)



def AuthSequenceB(dynamic_socket, peerAdd, init_msg):
   global server_socket
   global sender_private_key
   global dh_aes_key
   print "AuthSequenceB"
   # decrypt peer's user name
   print "len(init_msg) = "+str(len(init_msg))
   dataRecv = RSADecrypt(init_msg, sender_private_key)
   r2 = dataRecv[0:32]
   peername = str(dataRecv[32:len(dataRecv)])
   # fetch peer's AuthKey
   N1 = os.urandom(32) 
   iv = os.urandom(16)  
   sendinfo = AESEncrypt('send '+peername, dh_aes_key, iv)
   send_msg = bytes(N1) + bytes(username + ',' + sendinfo)
   #encrypt username and list command using new aes key and then encrypt the aes key using server public key
   sym_key = keygen()
   encrypted_send = AESEncrypt(send_msg, sym_key, iv)

   cipher_sym_key = RSAEncrypt(sym_key, serverpubkey)
   send_msg = bytes(0x01) + bytes(iv) + bytes(cipher_sym_key) + bytes(encrypted_send)
   print('Sending send command')
   server_socket.sendto(send_msg, (serverIP, int(serverPort)))
   (Dport, addr) = server_socket.recvfrom(4096)
   #receive peer info from the server 
   (dataRecv, addr) = server_socket.recvfrom(4096)
   offset = 0
   iv1 = dataRecv[offset:offset+16]
   offset += 16
   ciphernew = dataRecv[offset:len(dataRecv)]
   #decrypt ciphernew
   peerInfo = AESDecrypt(dh_aes_key, iv1, ciphernew)
   print "peerInfo = "+peerInfo
   peerRSAKey = peerInfo.split(',')[2]
   peerRSAKey =  serialization.load_pem_public_key(peerRSAKey, backend=default_backend())

   # finish the authentication
   r1 = os.urandom(32)
   r1_e = RSAEncrypt(r1, peerRSAKey)
   msg = bytes(r2)+bytes(r1_e)
   print "send reply to peer:"+peerAdd[0]+":"+str(peerAdd[1])
   dynamic_socket.sendto(msg, (peerAdd[0], int(peerAdd[1])))
   # waiting for CommKey
   (dataRecv, addr) = dynamic_socket.recvfrom(4096)
   r1_d = dataRecv[0:32]
   if r1_d!=r1:
      print 'verificatoin failed'
      return
   peerRSACommKey = dataRecv[32:len(dataRecv)]
   peerRSACommKey = decryptSendMsg(peerRSACommKey, sender_private_key, peerRSAKey)
   # generate CommKey and send to peer
   try:
      comm_private_key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=2048,
      backend=default_backend())
   except:
      print("The provided backend does not implement RSABackend")
      return None

   #obtain the public key from the private key generated using RSA
   comm_public_key = comm_private_key.public_key()
   try:
      pem = comm_public_key.public_bytes(
           encoding=serialization.Encoding.PEM,
           format=serialization.PublicFormat.SubjectPublicKeyInfo)
      pem_s = comm_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
   )
   except:
      print("Serialization failed")
      return None
   pem_cipher = encryptSendMsg(peerRSAKey, sender_private_key, pem)
   dynamic_socket.sendto(pem_cipher, (peerAdd[0], int(peerAdd[1])))
   return (pem_s, peerRSACommKey)

def MsgSendSequence(peername, msg):
   # fetch user info from server
   global dh_aes_key
   global serverpubkey
   global serverIP
   global username
   try:
      #format of send command {Alice,K{send Bob}} server-public-key
      #encrypt the list command using the DH shared key
      N1 = os.urandom(32) 
      iv = os.urandom(16)
      sendinfo = AESEncrypt('send '+peername, dh_aes_key, iv)
      send_msg = bytes(N1) + bytes(username + ',' + str(sendinfo))
      #encrypt username and list command using new aes key and then encrypt the aes key using server public key
      sym_key = keygen()
      encrypted_send = AESEncrypt(send_msg, sym_key, iv)

      cipher_sym_key = RSAEncrypt(sym_key, serverpubkey)
      send_msg = bytes(0x01) + bytes(iv) + bytes(cipher_sym_key) + bytes(encrypted_send)
      print('Sending send command')
      server_socket.sendto(send_msg, (serverIP, int(serverPort)))
      (Dport, addr) = server_socket.recvfrom(4096)

      #receive peer info from the server 
      (dataRecv, addr) = server_socket.recvfrom(4096)
      offset = 0
      iv1 = dataRecv[offset:offset+16]
      offset += 16
      ciphernew = dataRecv[offset:len(dataRecv)]
      #decrypt ciphernew
      peerInfo = AESDecrypt(dh_aes_key, iv1, ciphernew)
      print "peerInfo = "+peerInfo
      (peerCommKey, comm_private_key, dynamic_socket, D_addr) = AuthSequenceA(peerInfo)
      # encrypt msg and send it to peer
      if (peerCommKey == None or comm_private_key == None):
         print "sending msg failed"
      peerCommKey = serialization.load_pem_public_key(
          peerCommKey,
          backend=default_backend()
      )
      comm_private_key = serialization.load_pem_private_key(
         comm_private_key,
         password=None,
         backend=default_backend()
      )
      msg = encryptSendMsg(peerCommKey, comm_private_key, msg)
      dynamic_socket.sendto(msg, (D_addr[0],int(D_addr[1])))
      print "msg has been sent"
   except socket.timeout:
      print "timeout error:", sys.exc_info()[0]
      return
   except:
      print "Unexpected error:", sys.exc_info()[0]
      return

def MsgRecvSequence(dynamic_socket, peerAdd, dataRecv):
   print "MsgRecvSequence"
   comm_private_key = None
   comm_public_key = None
   try:
      (comm_private_key, comm_public_key) = AuthSequenceB(dynamic_socket, peerAdd, dataRecv)
      # decrypt msg and output it on console
      if comm_private_key == None or comm_public_key == None:
         print "MsgRecvSequence Error"
         return
      (dataRecv, addr) = dynamic_socket.recvfrom(4096)

      comm_public_key = serialization.load_pem_public_key(
          comm_public_key,
          backend=default_backend()
      )
      comm_private_key = serialization.load_pem_private_key(
         comm_private_key,
         password=None,
         backend=default_backend()
      )

      msg = decryptSendMsg(dataRecv, comm_private_key, comm_public_key)
      print "Message Recieved : "
      print msg
   except socket.timeout:
      print "socket timeout"
      return
   except:
      print "Unexpected error:", sys.exc_info()[0]

def LoginSequence(username, password):
   global server_socket
   global serverIP
   global serverPort
   global client_socket
   global commonPort
   global dh_aes_key
   global serverpubkey
   global Dport
   global sender_private_key

   #compute the nonce, a random no. of 32 bit, W from password 
   nonce = os.urandom(32)
   W = hash32(password)
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

   (dataRecv, addr) = server_socket.recvfrom(4096)
   offset = 0
   iv = dataRecv[offset:offset+16]
   offset += 16
   ciphertext = dataRecv[offset:len(dataRecv)]
   dh_aes_key = aeskeygen(u.key)
 
   #decrypt the ciphertext using the key_sym and iv
   plaintext = AESDecrypt(dh_aes_key, iv, ciphertext)
   msg = str(bytes(plaintext))
   print('Received ACK')

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
   global serverIP
   #format of list command {Alice,K{list}} server-public-key
   #encrypt the list command using the DH shared key
   N1 = os.urandom(32) 
   iv = os.urandom(16)	
   listinfo = AESEncrypt('list', dh_aes_key, iv)

   list_msg = bytes(N1) + bytes(clientinfo + ',' + listinfo)
   #encrypt username and list command using new aes key and then encrypt the aes key using server public key
   sym_key = keygen()
   encrypted_list = AESEncrypt(list_msg, sym_key, iv)

   cipher_sym_key = RSAEncrypt(sym_key, serverpubkey)
   send_list_msg = bytes(0x01) + bytes(iv) + bytes(cipher_sym_key) + bytes(encrypted_list)
   print('Sending list command')
   server_socket.sendto(send_list_msg, (serverIP, int(serverPort)))
   (Dport, addr) = server_socket.recvfrom(4096)

   #receive list of users active on the server 
   (dataRecv, addr) = server_socket.recvfrom(4096)
   offset = 0
   iv1 = dataRecv[offset:offset+16]
   offset += 16
   ciphernew = dataRecv[offset:len(dataRecv)]
   #decrypt ciphernew
   text = AESDecrypt(dh_aes_key, iv1, ciphernew)
   print('List of Users currently active:')
   print str(bytes(text))

def LogoutSequence(clientInfo):
   global dh_aes_key
   global serverpubkey
   global serverIP

   #message format for logout {username,K{logout},N1}serverpublickey
   #encrypt the logout command using the DH shared key
   iv = os.urandom(16)
   logoutinfo = AESEncrypt('logout', dh_aes_key, iv)

   #compute the nonce
   N1 = os.urandom(32)
   exitinfo = bytes(N1) + bytes(clientInfo + ',' + logoutinfo)

   #encrypt using aes key
   sym_key=keygen()
   ciphertext = AESEncrypt(exitinfo, sym_key, iv)

   #encrypt the symmetric key with rsa public key
   cipher_sym_key = RSAEncrypt(sym_key, serverpubkey)

   exit_msg = bytes(0x01) + bytes(iv) + bytes(cipher_sym_key) + bytes(ciphertext)
   server_socket.sendto(exit_msg, (serverIP, int(serverPort))) 
   (Dport, addr) = server_socket.recvfrom(4096)
   (dataRecv, addr) = server_socket.recvfrom(4096)
   offset = 0
   newiv = dataRecv[offset:offset+16]
   offset += 16
   cipher = dataRecv[offset:len(dataRecv)]
   
   text = AESDecrypt(dh_aes_key, newiv, cipher)
   NONCE1 = text[0:32]
   NONCE2 = text[32:len(text)]
   try:
      if NONCE1 == N1:
         iv1 = os.urandom(16)
         challenge_response = bytes(NONCE2) + bytes(clientInfo)
         #encrypt using aes key
         sym_key1=keygen()
         ciphertext1 = AESEncrypt(challenge_response, sym_key1, iv1)
  
         #encrypt the symmetric key with rsa public key
         cipher_sym_key1 = RSAEncrypt(sym_key1, serverpubkey)
         exitmsg = bytes(iv1) + bytes(cipher_sym_key1) + bytes(ciphertext1)
         server_socket.sendto(exitmsg, (serverIP, int(Dport)))
   except:
       print('Failed authentication')
       raise
   finally:
       exit(0)
   pass

if __name__ == "__main__":
   main(sys.argv[1:])
