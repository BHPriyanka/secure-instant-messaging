import sys, getopt
import socket
import thread
import time

ClientList = []

def hash32(value):
    return hash(value) & 0xffffffff

def main(argv):
   serverPort = ''
   if len(argv) != 2:
      print 'ChatServer.py -p <serverPort>'
      sys.exit(2)
   try:
      opts, args = getopt.getopt(argv,"hp:")
   except getopt.GetoptError:
      print 'ChatServer.py -p <serverPort>'
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-h':
         print 'ChatServer.py -p <serverPort>'
         sys.exit()
      elif opt =="-p":
         serverPort = arg
   try:
      server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Use UDP for communication
      server_socket.bind((socket.gethostname(), int(serverPort)))
      print 'Server Initialized at '+socket.gethostname()+':'+serverPort
      thread.start_new_thread(RxTask,(server_socket,))
   except:
      print 'error when init socket, exit...'
      sys.exit(2)
   while True:
      pass

def RxTask(server_socket):
   # GREETING for login sequence init
   # MESSAGE for any other cmd type, which is encrypted
   # MsgType|User|MsgBody
   global ClientList
   while True:
      try:
         data, addr = server_socket.recvfrom(2048)
         print "received message:", data
         print "received addr:", addr
         dataComponents = data.split('|')
         msgType = dataComponents[0]
         user = dataComponents[1]
         msgBody= dataComponents[2]
         if msgType == 'GREETING':
            portInfo = createDynamicPort(LoginSequence, user, msgBody)
            TxTask(server_socket,serverIP, serverPort, portInfo)
         elif msgType == 'MESSAGE':
            portInfo = createDynamicPort(user, msgBody)
            TxTask(server_socket,serverIP, serverPort, portInfo):
         time.sleep(10)
      except socket.error:
         print 'Rx socket error!'
         sys.exit(2)
      except:
         continue

def TxTask(server_socket,serverIP, serverPort, msg):
   try:
      server_socket.sendto(msg, (serverIP, serverPort))
      #print "sending message:", msg
   except socket.error:
      print 'Tx socket error!'
      sys.exit(2)


def LoginSequence(clientInfo):
   PDMSequence(clientInfo)
   # ACK
   # waiting for the client send common port info and peer AuthKey
   # register those into eph-table
   pass

def PDMSequence(clientInfo):
   pass

def FetchSequence(clientInfo):
   pass

def LogoutSequence(clientInfo):
   pass

def createDynamicPort(user, msgBody):
   # decrypt sequence type using user's K
   createDynamicPort(sequenceType, user, msgBody)

def createDynamicPort(sequenceType, user, msgBody):
   # init new RxTask thread for the port
   # port will close after specified sequence
   pass

if __name__ == "__main__":
   main(sys.argv[1:])
