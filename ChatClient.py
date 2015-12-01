import sys, getopt
import socket
import thread
import time
import re

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
   except:
      print 'error when init socket, exit...'
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
   PDMSequence(username, password)
   # waiting for ACK
   # send common port info and peer AuthKey
   pass

def PDMSequence(username, password):
   pass

def FetchSequence(clientInfo):
   pass

def LogoutSequence(clientInfo):
   pass

if __name__ == "__main__":
   main(sys.argv[1:])
