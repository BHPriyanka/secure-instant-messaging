import sys, getopt
import socket
import thread
import time

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
         server_socket.sendto(dynamic_port, (serverIP, commonPort))
         thread.start_new_thread(task,(dynamic_socket, dataRecv))
      except socket.error:
         print 'socket error!'
         sys.exit(2)
      except:
         continue

def createDynamicPort():
   Dsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Use UDP for communication
   Dsocket.bind((socket.gethostname(), 0))
   return (Dsocket, Dsocket.getsockname()[1])

def task(dynamic_socket, dataRecv):
   # parse dataRecv: type|iv|key_sym|ciphertext
   msg_type = dataRecv[0]
   try:
      if msg_type == 0x00:
         LoginSequence(dynamic_socket,dataRecv)
      elif msg_type == 0x01:
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
   finally:
      dynamic_socket.close()


def LoginSequence(clientInfo):
   PDMSequence(clientInfo)
   # ACK
   # waiting for the client send common port info and peer AuthKey
   # register those into eph-table
   pass

def PDMSequence(clientInfo):
   pass

def ListSequence(clientInfo):
   pass

def FetchSequence(clientInfo):
   pass

def LogoutSequence(clientInfo):
   pass

if __name__ == "__main__":
   main(sys.argv[1:])
