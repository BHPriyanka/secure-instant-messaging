import sys, getopt, os
import socket, re
import thread
import time
import base64
import hashlib, ctypes
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
from general_functions import aeskeygen, keygen, RSADecrypt, RSAEncrypt, AESDecrypt, AESEncrypt, extractmsg

ClientList = []
user_networkinfo = {}
user_DHkey = {}
user_moduli = []

def hash32(value):
   # use this to calculate W from password string.
   return hash(value) & 0xffffffff

def main(argv):
   global serverprivkey

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
      # server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      server_socket.bind((socket.gethostname(), int(commonPort)))
      print 'Server Initialized at '+server_socket.getsockname()[0]+':'+commonPort
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
         sys.exit(2)
      except exceptions.KeyboardInterrupt:
         sys.exit(2)
      except exceptions.KeyError:
         print 'user does not exist'
         continue
      except:
         raise
         continue

def createDynamicPort():
   Dsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Use UDP for communication
   # Dsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
   Dsocket.bind((socket.gethostname(), 0))
   # Every dynamic port will timeout in 5 seconds
   Dsocket.settimeout(20)
   return (Dsocket, Dsocket.getsockname()[1])

def task(dynamic_socket, addr, dataRecv):
   global serverprivkey
   global user_DHkey

   # parse dataRecv: type|iv|key_sym|ciphertext
   msg_type = dataRecv[0]
   try:
      if msg_type == bytes(0x00):
         LoginSequence(dynamic_socket, addr, dataRecv)
         print('LOGIN SUCCESSFUL')
         print('List Of Services provided the Server')
         print('1. LIST')
         print('2.SEND')
         print('3.LOGOUT')
      elif msg_type == bytes(0x01):
         (iv, nonce, username, cmd_cipher) = extractmsg(serverprivkey, dataRecv)
         dhkey = user_DHkey[username]
         cmd_info = AESDecrypt(dhkey, iv, cmd_cipher)
         cmd = str(bytes(cmd_info)).split(' ')[0]
         
         if cmd == 'list':
            ListSequence(dynamic_socket, addr, username)
         elif cmd == 'send':
            peername = str(bytes(cmd_info)).split(' ')[1]
            FetchSequence(dynamic_socket, addr, username, peername)
         elif cmd == 'exit':
            LogoutSequence(dynamic_socket, username, cmd)
   except:
      traceback.print_exc()
      print "task error:", sys.exc_info()[0]
   finally:
      dynamic_socket.close()

def LoginSequence(dynamic_socket, addr, dataRecv):
   global user_DHkey
   global user_networkinfo
   global serverprivkey

   print 'LoginSequence'
 
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
   key_sym = RSADecrypt(cipher_key_sym, serverprivkey)

   #decrypt the ciphertext using the key_sym and iv
   plaintext = AESDecrypt(key_sym, iv , ciphertext)
   nonce = bytes(plaintext)[0:32]
   plaintext = str(bytes(plaintext[32:len(bytes(plaintext))]))
   
   #get data from plaintext
   split_data = plaintext.split(',')
   username = split_data[0]
   #2^a mod p
   client_dh_pub_key = split_data[1]
   client_rsa_pub_key = split_data[2]
   client_rsa_auth_key =  serialization.load_pem_public_key(client_rsa_pub_key, backend=default_backend())

   #calculate 2^b mod p
   u = DiffieHellman()
   b = str(u.privateKey)
   dh_key_server = str(u.publicKey)
   p = str(u.prime)
   u.genHashSecret(client_dh_pub_key)
   msg = nonce + dh_key_server + ',' + u.hashsecret

   #generate a aes key , iv and use it to encrypt the above msg
   aes_key = keygen()
   iv = os.urandom(16)
   ciphertext = AESEncrypt(msg, aes_key, iv)

   #encrypt the symmetric key with client's rsa public key
   cipher_key_sym = RSAEncrypt(aes_key, client_rsa_auth_key)

   #constant for GREETING is 0x00
   server_first_msg = bytes(0x00)  + bytes(iv) + bytes(cipher_key_sym) + bytes(ciphertext)

   print 'reply first msg to client'
   dynamic_socket.sendto(server_first_msg, (addr[0], int(addr[1])))

   (dataRecv, addr) = dynamic_socket.recvfrom(4096)
   print('Verifying the hashes computed and received')
  
   try:
      if dataRecv == u.hashsecret:
         u.genKey(client_dh_pub_key)
      else:
         print('hashes does not match')
         sys.exit(2)
   except:
     print('hashes does not match')
     sys.exit(2)
   
   print('Sending ACK')
   sym_key_shared = aeskeygen(u.key)
   iv = os.urandom(16)
   acknowledge = AESEncrypt('ACK', sym_key_shared, iv)
   msg = bytes(iv) + bytes(acknowledge)
   dynamic_socket.sendto(msg, (addr[0], int(addr[1])))

   print('Waiting for networkinfo')
   (dataRecv, addr) = dynamic_socket.recvfrom(4096)
   offset = 0
   new_iv = dataRecv[offset:offset+16]
   offset += 16
   iv = dataRecv[offset:offset+16]
   offset += 16
   cipher_key_new = dataRecv[offset:offset+256]
   offset += 256
   nwciphertext = dataRecv[offset:len(dataRecv)]
   # decrypt cipher_key_new with reciever's private key
   new_key_sym = RSADecrypt(cipher_key_new, serverprivkey)

   #decrypt the nwciphertext 
   plaintext = AESDecrypt(new_key_sym, new_iv, nwciphertext)
   split_data = plaintext.split(',')
   user = str(bytes(split_data[0]))
   encnwinfo = split_data[1]

   #decrypt the nwinfo uing DH key
   plaintext = AESDecrypt(sym_key_shared, iv, encnwinfo)
   ip_address = plaintext.split(',')[0]
   port_num = plaintext.split(',')[1]
   print('Received common port and ip')
  
   #register those into eph-table
   user_networkinfo.setdefault(username, []).append(ip_address)
   user_networkinfo.setdefault(username, []).append(port_num)
   user_networkinfo.setdefault(username, []).append(client_rsa_pub_key)
   
   user_DHkey[username] = sym_key_shared
   print('Registered the client')
  
   #-------------------------------------------------

   pass

def ListSequence(dynamic_socket, addr, username):
   global serverprivkey
   global user_DHkey
   global user_networkinfo
   
   dhkey = None
   try:
      dhkey = user_DHkey[username]
   except:
      print('Client does not exist')
  
   #use this shared key to encrypt the list of users
   list_users = user_networkinfo.keys()
   iv = os.urandom(16)
   enc_list_users = AESEncrypt(str(list_users)[1:-1], dhkey, iv)
   msg = bytes(iv) + bytes(enc_list_users)
   #print hexlify(dhkey)
   dynamic_socket.sendto(msg, (addr[0], int(addr[1])))

def FetchSequence(dynamic_socket, addr, username, peername):
   global serverprivkey
   global user_DHkey
   global user_networkinfo

   peer_ip = ""
   peer_port = ""
   peer_key = ""
   
   dhkey = None
   try:
      dhkey = user_DHkey[username]  
   except:
      print('Client does not exist')
      return
  
   #use this shared key to encrypt the list of users
   peer_info = user_networkinfo[peername]
   peer_ip = peer_info[0]
   peer_port = peer_info[1]
   peer_key = peer_info[2]
   iv = os.urandom(16)
   enc_peer_info = AESEncrypt(peer_ip+","+peer_port+","+peer_key, dhkey, iv)
   msg = bytes(iv) + bytes(enc_peer_info)
   #print hexlify(dhkey)
   dynamic_socket.sendto(msg, (addr[0], int(addr[1])))
   print('Sent peer info')

def LogoutSequence(dynamic_socket, addr, username, nonce):
  global serverprivkey
  global user_DHkey
  global user_networkinfo
  #print('user_DHkey')
  #print('-----------------------------------')
  #print(user_DHkey)
  #print('user_networkinfo')
  #print('------------------------------------')
  #print(user_networkinfo)
  try:
      dhkey = user_DHkey[username]
  except:
      print('Client does not exist')
  #compute the nonce
  N2 = os.urandom(32)
  #K{N1,N2}
  #encrypt the logout command using the DH shared key
  iv = os.urandom(16)
  send_nonce = bytes(nonce) + bytes(N2) 
  logoutinfo = AESEncrypt(send_nonce, dhkey, iv)
  nonce_msg = bytes(iv) + bytes(logoutinfo)
  
  dynamic_socket.sendto(nonce_msg, (addr[0], int(addr[1])))
  (dataRecv, addr) = dynamic_socket.recvfrom(4096)
  offset = 0
  newiv = dataRecv[offset:offset+16]
  offset += 16
  cipher_sym_key1 = dataRecv[offset:offset+256]
  offset += 256
  ciphertext1 = dataRecv[offset:len(dataRecv)]

  # decrypt key_sym with reciever's private key
  key_sym = RSADecrypt(cipher_sym_key1, serverprivkey)

  #decrypt the ciphertext 
  plaintext = AESDecrypt(key_sym, newiv , ciphertext1)
  nonce = plaintext[0:32]
  username = str(bytes(plaintext[32:len(bytes(plaintext))]))
  print('Deleting User',username,'from the database')
  try:
    del user_DHkey[username]
    del user_networkinfo[username]
  except:
    print('User is not present in the existing database')
  #print(user_DHkey)
  print('----------------------------------------------------')
  #print(user_networkinfo)
  #print('--------------------------------------------------')
  pass


if __name__ == "__main__":
   main(sys.argv[1:])
