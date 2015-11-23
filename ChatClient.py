import sys, getopt
import socket
import thread
import time
import re

def main(argv):
   serverIP = ''
   serverPort = ''
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
   #print 'serverIP is :', serverIP
   #print 'serverPort is :', serverPort

   try:
      # Server Communication Port
      server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  ## Use UDP for communication
      server_socket.bind((socket.gethostname(), 0))   #dynamically allocate unprivileged random port
      print 'Server Communication Port at '+server_socket.getsockname()[0]+":"+str(server_socket.getsockname()[1])

      # Common Port
      client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  ## Use UDP for communication
      client_socket.bind((socket.gethostname(), 0))   #dynamically allocate unprivileged random port
      print 'Common Port at '+client_socket.getsockname()[0]+":"+str(client_socket.getsockname()[1])
      # passively listening on incomming conncetion from other clients.
      thread.start_new_thread(RxTask,(server_socket,))
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
      elif cmdComponents[0] == 'send':
         user = cmdComponents[1]
         msg = cmdComponents[2]
         MsgSendSequence(user, msg)



def RxTask(client_socket):
   while True:
      try:
         data, addr = client_socket.recvfrom(1024)
         msgType = data.split('|')[0]
         msgBody= data.split('|')[1]
         if msgType == 'MESSAGE':
            portInfo = createDynamicPort(MsgRecvSequence, user, msgBody)
            TxTask(server_socket,serverIP, serverPort, portInfo)
         time.sleep(10)
      except socket.error:
         print 'Rx socket error!'
         sys.exit(2)
      except:
         continue

def TxTask(client_socket, serverIP, serverPort):
   while True:
      MESSAGE = "MESSAGE"+"|"+raw_input()
      try:
         client_socket.sendto(MESSAGE, (serverIP, int(serverPort)))
      except socket.error:
         print 'Tx socket error!'
         sys.exit(2)
      time.sleep(10)

def AuthSequenceA(peerInfo):
   # sending GREETING to another client
   # waitng to receive portInfo
   # use this port info to finish authentication
   # generate CommKey and send to peer
   pass

def AuthSequenceB():
   # decrypt peer's user name
   # fetch peer's AuthKey
   # finish the authentication
   # waiting for CommKey
   # generate CommKey and send to peer
   pass

def MsgSendSequence(user, msg):
   # fetch user info from server
   AuthSequenceA(peerInfo)
   # encrypt msg and send it to peer

def MsgRecvSequence():
   AuthSequenceB()
   # decrypt msg and output it on console

def LoginSequence(clientInfo):
   PDMSequence(clientInfo)
   # waiting for ACK
   # send common port info and peer AuthKey
   pass

def PDMSequence(clientInfo):
   pass

def FetchSequence(clientInfo):
   pass

def LogoutSequence(clientInfo):
   pass

def createDynamicPort(sequenceType):
   # init new RxTask thread for the port
   # port will close after specified sequence
   pass

if __name__ == "__main__":
   main(sys.argv[1:])