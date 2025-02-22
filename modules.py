from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def encryption_AES(message, secret_key):
    """
    This function takes a message and a secret key and encrypts it via AES in ECB cipher mode.

    Parameters:
    message (string): message to be sent.
    secret_key (bytes): secret key between two entities.

    Returns:
    Bytes: encrypted message.
    """
    cipher = AES.new(secret_key, AES.MODE_ECB)

    #pkcs7 is compatible with pkcs5. The latter is only compatible with block size 8 whereas pkcs7 is compatible 
    #with multiple block sizes. AES block size is 16 bytes
    padded = pad(message.encode('utf-8'), block_size=16,style='pkcs7')
    encrypted = cipher.encrypt(padded)

    return encrypted


def decryption_AES(encrypted_message,secret_key):
    """
    This function takes a message encrypted by AES with ECB cipher mode and decrypts it.

    Parameters:
    encrypted_message (bytes): message to be decrypted.
    secret_key (bytes): secret key between two entities.

    Returns:
    string: decrypted message in plaintext.
    """
    
    cipher = AES.new(secret_key, AES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted_message)
    decrypted_message = unpad(decrypted, block_size=16,style='pkcs7').decode('utf-8')
    
    return decrypted_message


def encryption_RSA(secret_key, public_key):
    """
    This function encrypts the secret key with public key of RSA

    Parameters:
    secret_key (bytes): secret key in hex
    public_key (RSAPublicKey): public key

    Returns:
    bytes: encrypted secret key
    """
    encrypted = public_key.encrypt(
        secret_key,  
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


def decryption_RSA(secret_key_encrypted, private_key):
    """
    This function decrypts the secret key with private key of RSA

    Parameters:
    secret_key_encrypted (bytes): secret key in bytes encrypted by RSA
    private_key (RSAPrivateKey): private key

    Returns:
    bytes: decrypted secret key 
    """
    decrypted = private_key.decrypt(
        secret_key_encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted