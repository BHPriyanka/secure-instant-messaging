import sys, getopt, socket
import thread, getpass
import time, re, ctypes,os
from binascii import hexlify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac
from DHExample import DiffieHellman, hash32
from utilities import aeskeygen, keygen, RSADecrypt, RSAEncrypt, AESDecrypt, AESEncrypt
from utilities import encryptSendMsg, decryptSendMsg

# Variables for certain constants
LengthN = 32
LengthIV =16
InitOffset =0
LengthKey = 256

# Local parameters
server_socket = None
serverCommPort = None
client_socket = None
commonPort = None
username = None
password = None
sender_private_key = None

# Remote parameters
serverIP = None
serverPort = None
dh_aes_key = None

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

   # Usage of Client program
   if len(argv) != 4:
      print 'ChatClient.py -s <serverIP> -p <serverPort>'
      sys.exit(2)
   try:
      opts, args = getopt.getopt(argv,"hs:p:")
   except getopt.GetoptError:
      print 'ChatClient.py -s <serverIP> -p <serverPort>'
      sys.exit(2)
   for opt, arg in opts:
      if opt =="-s":
         serverIP = arg
      elif opt =="-p":
         serverPort = arg
      else:
        print 'ChatClient.py -s <serverIP> -p <serverPort>'
        sys.exit()

   try:
      # Server Communication Port
      (server_socket,serverCommPort) = createDynamicPort()
      print 'Server Communication Port at '+server_socket.getsockname()[0]+":"+str(server_socket.getsockname()[1])
      # Common Port
      (client_socket, commonPort) = createDynamicPort()
      client_socket.settimeout(None)
      print 'Common Port at '+client_socket.getsockname()[0]+":"+str(client_socket.getsockname()[1])

      # Start login sequence
      username = raw_input("User:")
      if not username:
         print 'Username cannot be blank'
         sys.exit(2)
      # password = raw_input("password:")
      password = getpass.getpass('Password:')
      LoginSequence(username, password)

      # Passively listening on incomming connection from other clients.
      thread.start_new_thread(listenTask,(client_socket,))
   except socket.timeout:
      print 'Connection timeout...'
      sys.exit(2)
   except :
      print 'Error when login, exit...'
      raise
      sys.exit(2)

   while True:
      # Cmd Task:
      # send username msg
      # list
      # block main thread until sequence finished
      inputStr = raw_input()
      cmdComponents = re.split('\s+', inputStr)
      if cmdComponents[0] == 'list':
         if len(cmdComponents)>1:
            print 'Usage: list'
            continue
         ListSequence(username)
      elif cmdComponents[0] == 'send':
         if len(cmdComponents)<3:
            print 'Usage: send USER MESSAGE'
            continue
         user = cmdComponents[1]
         msg = ' '.join(cmdComponents[2:len(cmdComponents)])
         MsgSendSequence(user, msg)
      elif cmdComponents[0] == 'logout':
         if len(cmdComponents)>1:
            print 'Usage: logout'
            continue
         LogoutSequence(username)
      else:
	print('Invalid Input by the User')
         
# Generation of Dynamic port
def createDynamicPort():
   Dsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Use UDP for communication
   Dsocket.bind((socket.gethostname(), 0))
   # every socket will timeout in 20 seconds!
   Dsocket.settimeout(20)
   return (Dsocket, Dsocket.getsockname()[1])


def listenTask(client_socket):
   print "Listening on "+client_socket.getsockname()[0]+":"+str(client_socket.getsockname()[1])
   while True:
      try:
         (dataRecv, addr) = client_socket.recvfrom(4096)
         print "Received message length:", len(dataRecv)
         print "Received addr:", addr
         (dynamic_socket, dynamic_port) = createDynamicPort()
         client_socket.sendto(str(dynamic_port), (addr[0], addr[1]))
         thread.start_new_thread(MsgRecvSequence,(dynamic_socket, addr, dataRecv))
      except socket.error:
         print 'ListenTask socket error!'
         sys.exit(2)
      except KeyboardInterrupt:
         sys.exit(2)
      except:
         print "Unexpected error:", sys.exc_info()[0]
         continue

# authentication for client A
def AuthSequenceA(peerInfo):
   global username
   global sender_private_key

   peer_ip = peerInfo.split(',')[0]                     # IP address of the peer
   peer_port = peerInfo.split(',')[1]                   # Port Number of the peer
   peer_authKey = peerInfo.split(',')[2]                # RSA Public key of the peer

   # Sending GREETING to another client
   (dynamic_socket, dynamic_port) = createDynamicPort()
   print "CreateDynamicPort for peer auth: " + str(dynamic_port)

   peer_authKey =  serialization.load_pem_public_key(peer_authKey, backend=default_backend())
   r2 = os.urandom(LengthN)
   greeting_msg = bytes(r2) + bytes(username)

   # Encrypt the greeting message with the rsa public key of the peer
   greeting_msg = RSAEncrypt(greeting_msg, peer_authKey)
   print "peer_ip = " + peer_ip
   print "peer_port = " + peer_port
   dynamic_socket.sendto(greeting_msg,(peer_ip,int(peer_port)))

   # Waitng to receive portInfo
   (Dport, addr) = dynamic_socket.recvfrom(4096)
   print "Dport = " + Dport

   (dataRecv, addr) = dynamic_socket.recvfrom(4096)
   # Use this port info to finish authentication

   if addr[0]!= peer_ip:
      print "Peer doesn't match... maybe impersonated..."
      return (None, None, dynamic_socket, addr)

   r2_d = dataRecv[0:LengthN]
   if r2_d != r2:
      print "R2 verification failed!"
      return (None, None, dynamic_socket, addr)

   r1_e = dataRecv[LengthN:len(dataRecv)]
   r1 = RSADecrypt(r1_e, sender_private_key)

   # Generate CommKey and send to peer
   try:
      comm_private_key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=2048,
      backend=default_backend())
   except:
      print("The provided backend does not implement RSABackend")
      return (None, None, dynamic_socket, addr)

   # Obtain the public key from the private key generated using RSA
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
      return (None, None, dynamic_socket, addr)

   pem_cipher = encryptSendMsg(peer_authKey, sender_private_key, pem)
   msg = bytes(r1)+bytes(pem_cipher)
   dynamic_socket.sendto(msg,(peer_ip, int(Dport)))
   (peerCommKey, addr) = dynamic_socket.recvfrom(4096)
   if addr[0]!= peer_ip:
      print "Peer doesn't match... maybe impersonated..."
      return (None, None, dynamic_socket, addr)
   peerCommKey = decryptSendMsg(peerCommKey, comm_private_key, peer_authKey)
   return (peerCommKey, pem_s, dynamic_socket, addr)

# Authentication for the Client B
def AuthSequenceB(dynamic_socket, peerAdd, init_msg):
   global server_socket
   global sender_private_key
   global dh_aes_key

   print "AuthSequenceB"

   # Decrypt peer's user name
   dataRecv = RSADecrypt(init_msg, sender_private_key)
   r2 = dataRecv[0:LengthN]
   peername = str(dataRecv[LengthN:len(dataRecv)])

   # Fetch peer's AuthKey
   N1 = os.urandom(LengthN) 
   iv = os.urandom(LengthIV)  
   sendinfo = AESEncrypt('send '+ peername, dh_aes_key, iv)
   send_msg = bytes(N1) + bytes(username + ',' + sendinfo)

   # Encrypt send_msg using new aes key and then encrypt the aes key using server public key
   sym_key = keygen()
   encrypted_send = AESEncrypt(send_msg, sym_key, iv)

   cipher_sym_key = RSAEncrypt(sym_key, serverpubkey)
   send_msg = bytes(0x01) + bytes(iv) + bytes(cipher_sym_key) + bytes(encrypted_send)
   print('Sending send command')
   server_socket.sendto(send_msg, (serverIP, int(serverPort)))

   (Dport, addr) = server_socket.recvfrom(4096)
   # Receive peer info from the server 
   (dataRecv, addr) = server_socket.recvfrom(4096)
   offset = InitOffset
   iv1 = dataRecv[offset:offset+LengthIV]
   offset += LengthIV
   ciphernew = dataRecv[offset:len(dataRecv)]

   # Decrypt ciphernew
   peerInfo = AESDecrypt(dh_aes_key, iv1, ciphernew)
   peerAdd_s = peerInfo.split(',')[0]
   if peerAdd_s!=peerAdd[0]:
      print "Peer doesn't match... maybe impersonated..."
      return

   peerRSAKey = peerInfo.split(',')[2]
   peerRSAKey =  serialization.load_pem_public_key(peerRSAKey, backend=default_backend())

   # Finish the authentication
   r1 = os.urandom(LengthN)
   r1_e = RSAEncrypt(r1, peerRSAKey)
   msg = bytes(r2)+bytes(r1_e)
   print "Send reply to peer: " + peerAdd[0] + " : " + str(peerAdd[1])
   dynamic_socket.sendto(msg, (peerAdd[0], int(peerAdd[1])))

   # Waiting for CommKey
   (dataRecv, addr) = dynamic_socket.recvfrom(4096)
   r1_d = dataRecv[InitOffset:LengthN]
   if r1_d!=r1:
      print 'Verification failed'
      return
   peerRSACommKey = dataRecv[LengthN:len(dataRecv)]
   peerRSACommKey = decryptSendMsg(peerRSACommKey, sender_private_key, peerRSAKey)

   # Generate CommKey and send to peer
   try:
      comm_private_key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=2048,
      backend=default_backend())
   except:
      print("The provided backend does not implement RSABackend")
      return None

   # Obtain the public key from the private key generated using RSA
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
   key = serialization.load_pem_public_key(peerRSACommKey, backend=default_backend())
   pem_cipher = encryptSendMsg(key, sender_private_key, pem)
   dynamic_socket.sendto(pem_cipher, (peerAdd[0], int(peerAdd[1])))

   return (peername, pem_s, peerRSACommKey)

# Send Message
def MsgSendSequence(peername, msg):
   # Fetch user info from server
   global dh_aes_key
   global serverpubkey
   global serverIP
   global username

   dynamic_socket = None
   try:
      # Format of send command {Alice,K{send Bob}} server-public-key
      # Encrypt the list command using the DH shared key
      N1 = os.urandom(LengthN) 
      iv = os.urandom(LengthIV)
      sendinfo = AESEncrypt('send '+peername, dh_aes_key, iv)
      send_msg = bytes(N1) + bytes(username + ',' + str(sendinfo))

      # Encrypt username and list command using new aes key and then encrypt the aes key using server public key
      sym_key = keygen()
      encrypted_send = AESEncrypt(send_msg, sym_key, iv)

      cipher_sym_key = RSAEncrypt(sym_key, serverpubkey)
      send_msg = bytes(0x01) + bytes(iv) + bytes(cipher_sym_key) + bytes(encrypted_send)
      print('Sending send command')
      server_socket.sendto(send_msg, (serverIP, int(serverPort)))
      (Dport, addr) = server_socket.recvfrom(4096)

      # Receive peer info from the server 
      (dataRecv, addr) = server_socket.recvfrom(4096)
      offset = InitOffset
      iv1 = dataRecv[offset:offset+LengthIV]
      offset += LengthIV
      ciphernew = dataRecv[offset:len(dataRecv)]

      # Decrypt ciphernew
      peerInfo = AESDecrypt(dh_aes_key, iv1, ciphernew)
      (peerCommKey, comm_private_key, dynamic_socket, D_addr) = AuthSequenceA(peerInfo)

      # Encrypt msg and send it to peer
      if (peerCommKey == None or comm_private_key == None):
         print "Sending msg failed"
      else:
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
      print "Message has been sent"
   except socket.timeout:
      print "Timeout... please try to re-send the command"
   except:
      print "Unexpected error:", sys.exc_info()[0]
   finally:
      if dynamic_socket != None:
         dynamic_socket.close()
      return

# Message Receive Sequence
def MsgRecvSequence(dynamic_socket, peerAdd, dataRecv):
   print "MsgRecvSequence"
   comm_private_key = None
   comm_public_key = None
   try:
      (peername, comm_private_key, comm_public_key) = AuthSequenceB(dynamic_socket, peerAdd, dataRecv)
      # Decrypt msg and output it on console
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
      print "Message Recieved From "+peername+" : "
      print msg
   except socket.timeout:
      print "socket timeout"
   except:
      print "Unexpected error:", sys.exc_info()[0]
   finally:
         dynamic_socket.close()

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

   # Compute the nonce, a random no. of 32 bit
   nonce = os.urandom(LengthN)
   u = DiffieHellman()

   # modular prime and private key for DH exchange
   p = str(u.prime)
   a = str(u.privateKey)

   # public key g^a mod p
   dh_pub_key = str(u.publicKey)

   # Generate client rsa auth key pair
   try:
      sender_private_key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=2048,
      backend=default_backend())
   except:
      print("The provided backend does not implement RSABackend")

   # Obtain the public key from the private key generated using RSA
   sender_public_key = sender_private_key.public_key()
   try:
      pem = sender_public_key.public_bytes(
           encoding=serialization.Encoding.PEM,
           format=serialization.PublicFormat.SubjectPublicKeyInfo)
   except:
      print("Serialization failed")

   # Get the server public key from the file
   try:
      with open('serverpubkey.pem', 'rb') as f1:
          serverpubkey = serialization.load_pem_public_key(f1.read(), backend=default_backend())
   except:
      print("The destination public key file is not present")
      sys.exit(2)

   msg = str(nonce) + username + ',' + str(dh_pub_key) + ',' + str(pem)
  
   # Encrypt using aes key
   key_sym=keygen()
   iv = os.urandom(16)
   ciphertext = AESEncrypt(msg, key_sym, iv)

   # Encrypt the symmetric key with rsa public key
   cipher_key_sym = serverpubkey.encrypt(key_sym, padding.OAEP( mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))
   
   # Constant for GREETING is 0x00
   greeting_msg = bytes(0x00)  + bytes(iv) + bytes(cipher_key_sym) + bytes(ciphertext)
   server_socket.sendto(greeting_msg, (serverIP, int(serverPort)))
   (Dport, addr) = server_socket.recvfrom(4096)
   (dataRecv, addr) = server_socket.recvfrom(4096)
   
   # Use Dport to finish the rest of sequence server_socket.sendto(other_msg, (serverIP, Dport))
   # Server_first_msg = bytes(0x00)  + bytes(iv) + bytes(cipher_key_sym) + bytes(ciphertext)
   # msg = nonce + dh_key_server + ',' + u.hashsecret
   cipher_key_sym = None
   ciphertext = None
   iv = None
   offset = InitOffset
   msg_type = dataRecv[offset]
   offset += 1
   iv = dataRecv[offset:offset+LengthIV]
   offset += LengthIV
   cipher_key_sym = dataRecv[offset:offset+LengthKey]
   offset += LengthKey
   ciphertext = dataRecv[offset:len(dataRecv)]

   # Decrypt key_sym with sender's private key
   key_sym = RSADecrypt(cipher_key_sym, sender_private_key)

   # Decrypt the ciphertext using the key_sym and iv
   plaintext = AESDecrypt(key_sym, iv, ciphertext)
   plaintext = bytes(plaintext)
   offset = InitOffset
   nonce1 = plaintext[offset:offset+LengthN]
   offset += LengthN
   nonce2 = plaintext[offset:offset+LengthN]
   offset += LengthN

   if nonce1 != nonce:
      print "Nonce N1 doesn't match"
      exit(2)

   # Get data from plaintext
   hash_secret = plaintext[offset:offset+LengthN]
   offset += LengthN
   dh_key_server_public = plaintext[offset:len(plaintext)]
   
   # Generate hash secret
   W = hash32(password)
   u.genHashSecret(W, dh_key_server_public)
  
   if hash_secret == u.hashsecret:
      # Generate DH shared key
      u.genKey(dh_key_server_public)
      u.genHashSecret1(W, dh_key_server_public)
      server_socket.sendto(str(nonce2)+u.hashsecret1, (serverIP, int(Dport)))
   else:
      print('Hashes do not match' )
      sys.exit(2)

   (dataRecv, addr) = server_socket.recvfrom(4096)
   offset =InitOffset
   iv = dataRecv[offset:offset+LengthIV]
   offset += LengthIV
   ciphertext = dataRecv[offset:len(dataRecv)]
   dh_aes_key = aeskeygen(u.key)
 
   # Decrypt the ciphertext using the key_sym and iv
   plaintext = AESDecrypt(dh_aes_key, iv, ciphertext)
   msg = str(bytes(plaintext))
   print('Received ACK')

   networkinfo = client_socket.getsockname()[0] + ',' + str(client_socket.getsockname()[1])

   # Encrypt the network info using DH Key
   iv = os.urandom(LengthIV)
   nwinfo = AESEncrypt(networkinfo, dh_aes_key, iv)

   # Encrypt username and encrypted networkinfo using new aes key , and encrypt sym key using rsa server ublic key
   new_iv = os.urandom(LengthIV)
   new_sym_key = keygen()
   msg_nwinfo = username + ',' + bytes(nwinfo)
   encrypted_msg = AESEncrypt(msg_nwinfo, new_sym_key, new_iv)

   # Encrypt the symmetric key with rsa public key
   cipher_new_key = RSAEncrypt(new_sym_key, serverpubkey)

   info_msg = bytes(new_iv) + bytes(iv) + bytes(cipher_new_key) + bytes(encrypted_msg)
   print('Sending common port info and peer AuthKey')
   server_socket.sendto(info_msg, (serverIP, int(Dport)))  
   pass

def ListSequence(clientinfo):
   global dh_aes_key
   global serverpubkey
   global serverIP

   # Format of list command {Alice,K{list}} server-public-key
   # Encrypt the list command using the DH shared key
   N1 = os.urandom(LengthN) 
   iv = os.urandom(LengthIV)	
   listinfo = AESEncrypt('list', dh_aes_key, iv)

   list_msg = bytes(N1) + bytes(clientinfo + ',' + listinfo)
   # Encrypt username and list command using new aes key and then encrypt the aes key using server public key
   sym_key = keygen()
   encrypted_list = AESEncrypt(list_msg, sym_key, iv)

   cipher_sym_key = RSAEncrypt(sym_key, serverpubkey)
   send_list_msg = bytes(0x01) + bytes(iv) + bytes(cipher_sym_key) + bytes(encrypted_list)
   print('Sending list command')
   server_socket.sendto(send_list_msg, (serverIP, int(serverPort)))
   (Dport, addr) = server_socket.recvfrom(4096)

   # Receive list of users active on the server 
   (dataRecv, addr) = server_socket.recvfrom(4096)
   offset = InitOffset
   iv1 = dataRecv[offset:offset+LengthIV]
   offset += LengthIV
   ciphernew = dataRecv[offset:len(dataRecv)]

   # Decrypt ciphernew
   text = AESDecrypt(dh_aes_key, iv1, ciphernew)
   print('List of Users currently active:')
   print str(bytes(text)).strip('')

def LogoutSequence(clientInfo):
   global dh_aes_key
   global serverpubkey
   global serverIP

   # Message format for logout {username,K{logout},N1}serverpublickey
   # Encrypt the logout command using the DH shared key
   iv = os.urandom(LengthIV)
   logoutinfo = AESEncrypt('logout', dh_aes_key, iv)

   # Compute the nonce
   N1 = os.urandom(LengthN)
   exitinfo = bytes(N1) + bytes(clientInfo + ',' + logoutinfo)

   # Encrypt using aes key
   sym_key=keygen()
   ciphertext = AESEncrypt(exitinfo, sym_key, iv)

   # Encrypt the symmetric key with rsa public key
   cipher_sym_key = RSAEncrypt(sym_key, serverpubkey)

   exit_msg = bytes(0x01) + bytes(iv) + bytes(cipher_sym_key) + bytes(ciphertext)
   server_socket.sendto(exit_msg, (serverIP, int(serverPort))) 
   (Dport, addr) = server_socket.recvfrom(4096)
   (dataRecv, addr) = server_socket.recvfrom(4096)

   offset = InitOffset
   newiv = dataRecv[offset:offset+LengthIV]
   offset += LengthIV
   cipher = dataRecv[offset:len(dataRecv)]
   
   text = AESDecrypt(dh_aes_key, newiv, cipher)
   NONCE1 = text[0:LengthN]
   NONCE2 = text[LengthN:len(text)]
   try:
      if NONCE1 == N1:
         iv1 = os.urandom(LengthIV)
         challenge_response = bytes(NONCE2) + bytes(clientInfo)
         # Encrypt using aes key
         sym_key1=keygen()
         ciphertext1 = AESEncrypt(challenge_response, sym_key1, iv1)
  
         # Encrypt the symmetric key with rsa public key
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
