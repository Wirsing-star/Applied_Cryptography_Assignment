import secrets
import hashlib
from modules import AES_encrypt,AES_decrypt,encrypt_RSA,decrypt_RSA
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

##### message to be sent #####

message = "Hello, world!"
byte_message = message.encode('utf-8')
bit_length = len(byte_message) * 8

print(f"Message to be encrypted: {message}\n")
print(f"Bit length of the message: {bit_length}\n")

##### Generate a random number ######
#By this construction, we have 2**256 different numbers to choose from which makes a brute
#force attack infeasable  

stop=2**256-1
random_number=secrets.randbelow(stop)

print(f"Random number: {random_number}\n")

##### Create secret key in bytes as SHA-256 hash value #####

h = hashlib.new('sha256')
h.update(str(random_number).encode('utf-8'))
secret_key=h.digest()
secret_key_hex=h.hexdigest()

print(f"SHA-256 secret hash key (hex): {secret_key_hex}\n")

##### AES encryption #####

encrypted_message = AES_encrypt(message, secret_key)
print(f"AES encrypted message (hex): {encrypted_message.hex()}\n")


##### Secret key RSA encryption #####

# Generate key pair for 2048-RSA 
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key=private_key.public_key()

#PEM-encoding for hex printing
public_key_pem=public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
print(f"RSA public key (hex):{public_key_pem.hex()}\n")


#Encrypt secret key
secret_key_encrypted= encrypt_RSA(secret_key,public_key)
print(f"RSA encrypted secret key (hex): {secret_key_encrypted.hex()}\n")


##### Concatenate #####

# we use raw binary format as there is no specification for the application's purpose. 
final_encryption = secret_key_encrypted + encrypted_message


########## Destination ########


##### Deconcatenation #####
#because of RSA scheme 2048-bit we know the length of the encrypted secret key:
secret_key_encrypted=final_encryption[0:256]
encrypted_message=final_encryption[256:len(final_encryption)]

##### decrypt secret key #####

decrypted_secret_key=decrypt_RSA(secret_key_encrypted,private_key)
print(f"RSA decrypted secret key (hex): {decrypted_secret_key.hex()}\n")

##### AES decrypt #####

decrypted_message=AES_decrypt(encrypted_message,decrypted_secret_key)
print(f"AES decrypted message: {decrypted_message}\n")

