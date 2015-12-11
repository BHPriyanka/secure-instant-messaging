import sys, getopt, os
import socket, re
import thread
import time
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
from utilities import aeskeygen, keygen, RSADecrypt, RSAEncrypt, AESDecrypt, AESEncrypt, extractmsg

# dictionary to store the Username,IP address, Port number and the RSA auth key of the users
user_networkinfo = {}

# dictionary to store the Username and the Diffie Hellman Shared key of the users
user_DHkey = {}

# dictionary to tore the Username and then moduli 2^W mod p of the users
user_moduli = {}

# Variables for Constants used
InitOffset = 0
LengthType = 1
LengthIV = 16
LengthN = 32
LengthKey = 256

# Funtion to compute the positive hash value of the password
def hash32(value):
   # use this to calculate W from password string.
   return hash(value) & 0xffffffff


def main(argv):
    # Private key and the user_moduli table are define to be global variables
    global serverprivkey
    global user_moduli
    commonPort = ''      # common port to which all the client connect to
   
    # Usage of the ChatServer program
    if len(argv) != 2:
      print 'ChatServer.py -p <commonPort>'
      sys.exit(2)

    try:
      opts, args = getopt.getopt(argv,"hp:")
    except getopt.GetoptError:
      print 'ChatServer.py -p <commonPort>'
      sys.exit(2)

    for opt, arg in opts:
      if opt == "-p":
         commonPort = arg
      else:
	print 'ChatServer.py -p <commonPort>'
	sys.exit()
    
    # Create and bind to the socket
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Use UDP for communication
        server_socket.bind((socket.gethostname(), int(commonPort)))       
        print 'Server Initialized at '+server_socket.getsockname()[0]+':'+commonPort
    except:
        print 'Error during init socket, exit...'
        sys.exit(2)

    # Loading user table and initialising all tables
    try:
      with open('username_mod.txt', 'r') as f:
          for line in f:
            name, mod = line.split(",")
            user_moduli[name] = mod
            user_DHkey[name] = None
            user_networkinfo[name] = []
    except:
      print("Loading user table failed!")
      sys.exit(2)

    # Listen from all clients bound to the server
    while True:
      try:
         dataRecv, addr = server_socket.recvfrom(4096)
         (dynamic_socket, dynamic_port) = createDynamicPort()                # Create Dynamic port for each client
         server_socket.sendto(str(dynamic_port), (addr[0], int(addr[1])))    # Sends the new port info to the client
         thread.start_new_thread(task,(dynamic_socket, addr, dataRecv))      
      except socket.error:
         print 'Socket error!'
         sys.exit(2)
      except exceptions.KeyboardInterrupt:
         sys.exit(2)
      except exceptions.KeyError:
         print 'User does not exist'
         continue
      except:
         raise
         continue

# Generate a dynamic port
def createDynamicPort():
   Dsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Use UDP for communication
   Dsocket.bind((socket.gethostname(), 0))
   # Every dynamic port will timeout in 120 seconds
   Dsocket.settimeout(120)
   return (Dsocket, Dsocket.getsockname()[1])

# Main thread of the server
def task(dynamic_socket, addr, dataRecv):
   global serverprivkey
   global user_DHkey

   # parse dataRecv: type|iv|key_sym|ciphertext
   # msg_type is considered as the placeholder to differentiate the type of message
   # 0x00 for the Greeting message
   # 0x01 for other messages
   msg_type = dataRecv[0]				       
   try:
      if msg_type == bytes(0x00):
         LoginSequence(dynamic_socket, addr, dataRecv)
      elif msg_type == bytes(0x01):
         (iv, nonce, username, cmd_cipher) = extractmsg(serverprivkey, dataRecv)
         dhkey = user_DHkey[username]                              # Fetch the DH shared key from the table for the current user
         cmd_info = AESDecrypt(dhkey, iv, cmd_cipher)	           
         cmd = str(bytes(cmd_info)).split(' ')[0]		   # Commands-list,send or logout
         
         if cmd == 'list':
            ListSequence(dynamic_socket, addr, username)           # Invokes ListSequence method
         elif cmd == 'send':
            peername = str(bytes(cmd_info)).split(' ')[1]
            FetchSequence(dynamic_socket, addr, username, peername)# Invokes FetchSequence method
         elif cmd == 'logout':
            LogoutSequence(dynamic_socket, addr, username, nonce)  # Invokes LogoutSequence method

   except socket.timeout:
      print 'Client socket timeout, ignore the request...'
   except:
      print "task error:", sys.exc_info()[0]
      raise
   finally:
      dynamic_socket.close()

# LoginSequence 
def LoginSequence(dynamic_socket, addr, dataRecv):
   global user_DHkey
   global user_networkinfo
   global serverprivkey

   print 'LoginSequence'
 
   # msg format greeting_msg = bytes(0x00)  + bytes(iv) + bytes(cipher_key_sym) + bytes(ciphertext)
   cipher_key_sym = None
   ciphertext = None
   iv = None
   moduli = None

   offset = InitOffset	                               # Initial offset
   msg_type = dataRecv[offset] 		               # byte 0 contains the msg_type
   offset += LengthType
   iv = dataRecv[offset:offset+16]		       # 16 bytes of IV
   offset += LengthIV
   cipher_key_sym = dataRecv[offset:offset+256]	       # 256 bytes of the symmetric key
   offset += LengthKey
   ciphertext = dataRecv[offset:len(dataRecv)]	       # The encrypted text

   # Load Private key of the server
   try:
       with open('serverprivkey.pem', 'rb') as f:
            serverprivkey = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
   except:
       print("The file specified does not exist")
       sys.exit(2)

   # Decrypt key_sym with reciever's private key
   key_sym = RSADecrypt(cipher_key_sym, serverprivkey)

   # Decrypt the ciphertext using the key_sym and iv
   plaintext = AESDecrypt(key_sym, iv , ciphertext)
   N1 = bytes(plaintext)[0:32]
   plaintext = str(bytes(plaintext[32:len(bytes(plaintext))]))
   
   # Get data from plaintext
   split_data = plaintext.split(',')
   username = split_data[0]

   # Check if the user already exists
   try:
    if user_networkinfo[username] != [] or user_DHkey[username] != None:
      print "User has already logged in!"
      return
   except:
    print "User doesn't exist!"
    return

   # DH public key - 2^a mod p and rsa public key of the client
   client_dh_pub_key = split_data[1]
   client_rsa_pub_key = split_data[2]
   client_rsa_auth_key =  serialization.load_pem_public_key(client_rsa_pub_key, backend=default_backend())

   u = DiffieHellman()
   b = str(u.privateKey)                             # DH private key of the server
   dh_key_server = str(u.publicKey)                  # DH public key of the server - 2^b mod p
   p = str(u.prime)                                  # p - prime number for DH
   moduli = user_moduli[username]                    # 2^W mod p
   u.genHashSecretM(moduli ,client_dh_pub_key)
   N2 = os.urandom(LengthN)
   msg = N1 + N2 + u.hashsecret + dh_key_server

   # Generate a aes key , iv and use it to encrypt the above msg
   aes_key = keygen()
   iv = os.urandom(LengthIV)
   ciphertext = AESEncrypt(msg, aes_key, iv)

   # Encrypt the symmetric key with client's rsa public key
   cipher_key_sym = RSAEncrypt(aes_key, client_rsa_auth_key)

   # Constant for GREETING is 0x00
   server_first_msg = bytes(0x00)  + bytes(iv) + bytes(cipher_key_sym) + bytes(ciphertext)
   print 'Received Greeting from: ',username

   dynamic_socket.sendto(server_first_msg, (addr[0], int(addr[1])))

   (dataRecv, addr) = dynamic_socket.recvfrom(4096)
   print('Verifying the hashes')
   _N2 = dataRecv[0:LengthN]
   if _N2!=str(N2):
    print "Nonce N2 doesn't match"
    return
  
   u.genHashSecretM1(moduli ,client_dh_pub_key)
   hash_recv = dataRecv[LengthN:len(dataRecv)]
   if hash_recv == u.hashsecret1:
      u.genKey(client_dh_pub_key)
   else:
      print('Hashes does not match')
      return
   print('Sending ACK')

   sym_key_shared = aeskeygen(u.key)                              # Generate AES key out of DH key
   iv = os.urandom(LengthIV)
   acknowledge = AESEncrypt('ACK', sym_key_shared, iv)            # Encrypt the ACK with the symmetric key
   msg = bytes(iv) + bytes(acknowledge)
   dynamic_socket.sendto(msg, (addr[0], int(addr[1])))            # Send the ACK to the client

   print('Waiting for Network Information')
   (dataRecv, addr) = dynamic_socket.recvfrom(4096)
   offset = InitOffset
   new_iv = dataRecv[offset:offset+LengthIV]
   offset += LengthIV
   iv = dataRecv[offset:offset+LengthIV]
   offset += LengthIV
   cipher_key_new = dataRecv[offset:offset+LengthKey]
   offset += LengthKey
   nwciphertext = dataRecv[offset:len(dataRecv)]

   # Decrypt cipher_key_new with server's private key
   new_key_sym = RSADecrypt(cipher_key_new, serverprivkey)

   # Decrypt the nwciphertext using symmetric key decryption
   plaintext = AESDecrypt(new_key_sym, new_iv, nwciphertext)
   split_data = plaintext.split(',')
   user = str(bytes(split_data[0]))
   enc_nwinfo = split_data[1]

   # Decrypt the nwinfo using DH key
   plaintext = AESDecrypt(sym_key_shared, iv, enc_nwinfo)
   ip_address = plaintext.split(',')[0]
   port_num = plaintext.split(',')[1]
   #print('Received common port and ip')
  
   # Register the client's network info along with the client rsa public key into user_networkinfo table
   user_networkinfo[username].append(ip_address)
   user_networkinfo[username].append(port_num)
   user_networkinfo[username].append(client_rsa_pub_key)
   
   # Register the DH shared key in the user_DHkey table
   user_DHkey[username] = sym_key_shared

   print('LOGIN SUCCESSFUL')
   print('------------------------------------------------------------------')
   pass

# List Command
def ListSequence(dynamic_socket, addr, username):
   global serverprivkey
   global user_DHkey
   global user_networkinfo
   
   dhkey = None
   try:
      dhkey = user_DHkey[username]                   # Fetch the DH shared key from table for the corresponding client
   except:
      print('Client does not exist')
  
   # Obtain the list of active users
   all_users = user_networkinfo.keys()
   list_users = []
   for user in all_users:
    if user_networkinfo[user] != []:
      list_users.append(user)

   # Use this shared key to encrypt the list of users
   iv = os.urandom(LengthIV)
   enc_list_users = AESEncrypt(str(list_users)[1:-1], dhkey, iv)
   msg = bytes(iv) + bytes(enc_list_users)
   dynamic_socket.sendto(msg, (addr[0], int(addr[1])))

# FetchSequence for send command
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
  
   # Use this DH shared key to encrypt the peer info
   peer_info = user_networkinfo[peername]
   peer_ip = peer_info[0]
   peer_port = peer_info[1]
   peer_key = peer_info[2]

   iv = os.urandom(LengthIV)
   enc_peer_info = AESEncrypt(peer_ip+","+peer_port+","+peer_key, dhkey, iv)
   msg = bytes(iv) + bytes(enc_peer_info)
   dynamic_socket.sendto(msg, (addr[0], int(addr[1])))

# Logout Sequence on issue of logout command by the user
def LogoutSequence(dynamic_socket, addr, username, N1):
  global serverprivkey
  global user_DHkey
  global user_networkinfo
  print 'LogoutSequence'
  
  dhkey = user_DHkey[username]

  # Compute the nonce
  N2 = os.urandom(LengthN)

  # Message format K{N1,N2}
  # Encrypt the logout command using the DH shared key
  iv = os.urandom(LengthIV)
  send_nonce = bytes(N1) + bytes(N2) 
  logoutinfo = AESEncrypt(send_nonce, dhkey, iv)
  nonce_msg = bytes(iv) + bytes(logoutinfo)
  dynamic_socket.sendto(nonce_msg, (addr[0], int(addr[1])))

  (dataRecv, addr) = dynamic_socket.recvfrom(4096)             # Receive the consecutive message form client
  offset = InitOffset
  newiv = dataRecv[offset:offset+LengthIV]
  offset += LengthIV
  cipher_sym_key1 = dataRecv[offset:offset+LengthKey]
  offset += LengthKey
  ciphertext1 = dataRecv[offset:len(dataRecv)]

  # Decrypt key_sym with server's private key
  key_sym = RSADecrypt(cipher_sym_key1, serverprivkey)

  # Decrypt the ciphertext 
  plaintext = AESDecrypt(key_sym, newiv , ciphertext1)
  nonce = plaintext[0:32]                                            # Nonce 
  username = str(bytes(plaintext[32:len(bytes(plaintext))]))         # Username

  print 'Deleting User: ',username
  try:
    user_DHkey[username] = None
    user_networkinfo[username] = []
  except:
    print('User is not present in the existing database')
  print('----------------------------------------------------')
  pass


if __name__ == "__main__":
   main(sys.argv[1:])
