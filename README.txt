README.txt  - Contains the List of usernames and their corresponding passwords which are used for the implementation


Installation Instructions for the Server and the Client
--------------------------------------------------------------------

Server
---------------------------------------------------------------
FileName: ChatServer.py
Usage: python ChatServer.py -p <ServerPort>

Files Used:

1. serverprivkey.pem  - Stores the Server private key in PEM format

2. serverpubkey.pem - Stores the public key of the server in PEM format. This key is used by all the clients for initial communication with the server

3. username_mod.txt - It stores the details of 6 usernames and their corresponding modular value derived from the password  which is of the form 2^W mod p
		      where W is the secret hash derived from the password

4. DHExample.py - Implements the key aspects of the Diffie Hellman Key exchange. It generates secret key of DH, hash secrets used in our protocol, prime number p	
		  of fixed group(17) , public and private key pair using the generator g and prime p
5. utilities.py - Implements the functions which are common to both client and server. Functions for RSA encryption and decryption, AES Encryption and decryption, 	
                  message extract are present



Client
-----------------------------------------------------------------
FileName: ChatClient.py
Usage: python ChatClient.py -s <ServerIP> -p <ServerPort>          ->Press Enter

Enter the usernames and the passwords specified in the README.txt
Password is a hidden input, hence it will not be displayed on the console

Username: a
Password: 1                    


Files Used:

1. DHExample.py
2. serverpubkey.pem
3. utilities.py


Additional File:

key_creation.py - File to generate the server <private,public> key pair. 
		     Note: the file has been compiled and the keys have been stored in separate files

--------------------------------------------------------------------------

List of Usernames and passwords supported in our implementation:
--------------------------------------------------------------------------

USERNAME                     PASSWORD
a                              1
b                              2
alice                          4lice1597
bob                            b0b$2007
boris                          boriS@123789XYZ
admin                          p4sSW0rd!!! 
