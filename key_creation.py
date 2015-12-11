from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

##Create the public-private key pair for the sender
#try:
#        sender_private_key = rsa.generate_private_key(
#        public_exponent=65537,
#        key_size=2048,
#        backend=default_backend()
#    )
#except:
#        print("The provided backend does not implement RSABackend")

##serializing the private key generated using the library methods
#try:
#        pem1 = sender_private_key.private_bytes(
#              encoding=serialization.Encoding.PEM,
#              format=serialization.PrivateFormat.TraditionalOpenSSL,
#              encryption_algorithm=serialization.NoEncryption()
#        )
#except:
#        print("Serialization failed")

##obtain the public key from the private key generated using RSA
#sender_public_key = sender_private_key.public_key()

#try:
#        pem2 = sender_public_key.public_bytes(
#               encoding=serialization.Encoding.PEM,
#               format=serialization.PublicFormat.SubjectPublicKeyInfo
#        )
#except:
#        print("Serialization failed")

##Generate the another pair of public-private key using RSA
try:
    dest_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
except:
     print("The provided backend does not implement RSABackend")

try:
        pem3 = dest_private_key.private_bytes(
              encoding=serialization.Encoding.PEM,
              format=serialization.PrivateFormat.TraditionalOpenSSL,
              encryption_algorithm=serialization.NoEncryption()
        )
except:
        print("Serialization failed")

#Extract the public key from the private key previously generated
dest_public_key = dest_private_key.public_key()
try:
        pem4 = dest_public_key.public_bytes(
              encoding=serialization.Encoding.PEM,
              format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
except:
        print("Serialization failed")

##Save the two public-private key pairs in four files.
##One file each for destination public key,destination private key,sender private key,sender public key.
##The name of the files are self interpreted
#try:
#    f = open('sendpubkey.pem','wb')
#except IOError:
#    print("The file you are trying to open does not exist")
#else: 
#    f.write(pem2)
#    f.close()

#try:
#    f=open('sendprivkey.pem','wb')
#except IOError:
#    print("The file you are trying to open does not exist")
#else:    
#    f.write(pem1)
#    f.close()

try:
    f = open('serverprivkey.pem','wb')
except IOError:
    print("The file you are trying to open does not exist")
else:
    f.write(pem3)
    f.close()

try:
    f= open('serverpubkey.pem','wb')
except IOError:
    print("The file you are trying to open does not exist")
else:
    f.write(pem4)
    f.close()
