import sys,getopt
import thread
import socket,time

#initializing the default values of port and host
PORT= ' '
HOST = '0.0.0.0'

#an array to store the clients
clients = []
    
def main(argv):   

#Check the usage of the command
    if len(argv) != 2:
       print("Usage: server.py -p <portnumber>")
       sys.exit(2) 
    try:
       opts, args = getopt.getopt(argv,"p:")
    except getopt.GetoptError:
       sys.exit(2)

#Read the port number from command line       
    for opt, arg in opts:
       if opt == "-p":
          PORT = int(arg)

#Create a socket with UDP and INET
    try:

        s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        print("Socket created")
    except socket.error:
        print("Failed to create socket. Error Code : ")
        sys.exit()

##Bind to the specified Host and Port
    try:
        s.bind((HOST,PORT))
    except socket.error:
        print("Bind failed. ")
        sys.exit()
	
#Start the thread message to receive messages from multiple clients
    thread.start_new_thread(receive_msg,(s,))
    try:
	while 1:
           pass
    except KeyboardInterrupt:
	print("Server closed")
	sys.exit(2)

def receive_msg(s):
    #for each message received from the client(one or more) do the following.
    while 1:
        try:
    	    
            d = s.recvfrom(4096)
            data = d[0]
            addr = d[1]
	    
	    cipher_key_sym = None
	    ciphertext = None
	    iv = None

	    offset = 0
 	    msg_type = data[offset]
	    offset += 1
	    iv = data[offset:offset+16]
	    offset += 16
	    cipher_key_sym = data[offset:offset+256]
	    offset += 256
	    ciphertext = data[offset:len(data)]
	    
	    try:
	        with open('serverprivkey.pem', 'rb') as f:
	        	serverprivkey = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
	    except:
	        print("The file specified does not exist")
	        sys.exit(2)

 # decrypt key_sym with reciever's private key
	    key_sym = serverprivkey.decrypt(
	        cipher_key_sym,
	        padding.OAEP(
	          mgf=padding.MGF1(algorithm=hashes.SHA1()),
   	          algorithm=hashes.SHA1(),
	          label=None
		  ))

#if the client sends a GREETING message,record the client if its 0x00
            if msg_type == '0x00':
                #clients.append(d)
                print("Accepted connection from : ")
		print(addr)
		 #decrypt the ciphertext using the key_sym and iv
		cipher = Cipher(algorithms.AES(key_sym), modes.OFB(iv), backend=default_backend())
		decryptor = cipher.decryptor()
		plaintext = decryptor.update(ciphertext) + decryptor.finalize()

		#get data from plaintext
		split_data = plaintext.split(',')

		username = split_data[0]
		nonce = split_data[1]
		#2^a mod p
		client_dh_pub_key = split_data[2]
		client_rsa_pub_key = split_data[3]
		#print(client_rsa_pub_key)
		client_rsa_auth_key =  serialization.load_pem_public_key(client_rsa_pub_key, backend=default_backend())
 #print(split_data[3])
 #print(username)
 #print(nonce)
 #print(client_dh_pub_key)
 #W = hash('chuty')
 #print(W)
 #calculate 2^b mod p
		u = DiffieHellman()
		b = str(u.privateKey)
		dh_key_server = str(u.publicKey)
		p = str(u.prime)

		u.genHashSecret(client_dh_pub_key)

 #print("Key:", hexlify(u.key))
 #print(hexlify(u.hashsecret))

                #generate a aes key , iv and use it to encrypt the above msg
		aes_key = keygen()
		iv = os.urandom(16)
		cipher = Cipher(algorithms.AES(aes_key), modes.OFB(iv), backend=default_backend())
		encryptor = cipher.encryptor()

		ciphertext = encryptor.update(msg) + encryptor.finalize()
 #encrypt the symmetric key with client's rsa public key
		cipher_key_sym = client_rsa_auth_key.encrypt(aes_key, padding.OAEP( mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))

 #constant for GREETING is 0x00
		server_first_msg = bytes(0x00)  + bytes(iv) + bytes(cipher_key_sym) + bytes(ciphertext)
 		thread.start_new_thread(SendMsg,(s,addr[0],addr[1],server_first_msg))

#If the message is anything else, broadcast it to all clients
    	    if data != "GREETING":
	
                #define the format of the message to be sent to the client
                inc = "INCOMING \n IP Address : " + addr[0] + "\n Port : " + str(addr[1]) + "\n " + data.strip()
		print("============================================================")
		print(inc)

		#for each client in the list create a thread
                for c in clients:
                    thread.start_new_thread(SendMsg,(s,c[1][0],c[1][1],inc))
                    time.sleep(5)	
        except socket.error:
        	print("BroadCast Error")
        	sys.exit(2)
        except:
            continue

#Function to send the message to the specified client
def SendMsg(socket,ip,port,msg):
     try:
	
        socket.sendto(msg, (ip, port))
     except:
          print("SendingFailed!")
          sys.exit(2)

if __name__ == "__main__":
   main(sys.argv[1:])


