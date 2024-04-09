import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
import argon2


def create_gcm(password):
    '''
    Creates AES256-GCM encoder passed off of the password provided.
    The encryption key is generated from argon2 using the supplied password.

    Parameters:
      - password: string of the user's encryption password.

    Returns:
      - AESGCM object for encrypting & decrypting file
    '''
    # Get key from password for encryption/decryption
    key = argon2.low_level.hash_secret_raw(password.encode("utf-8"), salt=b"somesalt", time_cost=1, memory_cost=8, parallelism=1, hash_len=32, type=argon2.low_level.Type.D)

    # Create implementation of AES256 using key
    try:
        gcm = AESGCM(key)
    except Exception as e:
        return e

    return gcm



def encrypt_string(gcm, text):
    """
    Encrypts the given string using the provided AES256-GCM implementation.

    Parameters:
        gcm (AESGCM): The AESGCM object for encrypting/decrypting.
        text (str): The string to be encrypted.

    Returns:
        bytes: The ciphertext.
    """
    # Generate a random 96-bit nonce
    nonce = os.urandom(12)

    # Encrypt the string into a bytes array of ciphertext
    ciphertext = gcm.encrypt(nonce, text.encode(), None)

    encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
    encoded_nonce = base64.b64encode(nonce).decode('utf-8')

    ciphertext = f"{encoded_ciphertext}:{encoded_nonce}".encode()

    return ciphertext


def decrypt_bytes(gcm, ciphertext):
    """
    Decrypts the given bytes using the provided AES256-GCM implementation.

    Parameters:
        gcm (AESGCM): The AESGCM object for encrypting/decrypting.
        ciphertext (bytes): The ciphertext to be decrypted.

    Returns:
        str: The decrypted plaintext.
        Exception: If any error occurs during execution.
    """
    # Split the ciphertext into nonce and encrypted data
    parts = ciphertext.split(':')
    encoded_ciphertext, encoded_nonce = parts

    encrypted_data = base64.b64decode(encoded_ciphertext)
    nonce = base64.b64decode(encoded_nonce)

    # Decrypt the ciphertext and validate the nonce
    try:
        plaintext = gcm.decrypt(nonce, encrypted_data, None)
    except Exception as e:
        print(f"decrypt_bytes: {e}")
        return e
    
    return plaintext.decode()

def encrypt_messages(password, filename, messages):
    """
    Encrypts the given messages into a file using the supplied password.

    Parameters:
        password (str): The encryption password.
        filename (str): The name of the file where the ciphertext will be stored.
        messages (list[str]): The messages to be encrypted and stored.

    Returns:
        Exception: If any error occurs during execution.
    """
    # Join the messages with newline characters
    joined_messages = "\n".join(messages)

    # Create the AES256-GCM object based on the supplied password
    gcm = create_gcm(password)

    # Encrypt the joined messages
    ciphertext = encrypt_string(gcm, joined_messages)

    # Write the ciphertext of the messages to the file
    with open(f"./hist/{filename}.bin", "wb") as file:
        file.write(ciphertext)


def decrypt_file(password, filename):
    try:
        # Create AES256-GCM object passed on supplied password
        gcm = create_gcm(password)

        # Read ciphertext from file
        with open(filename, 'rb') as file:
            ciphertext = file.read()

        # Decrypt & print plaintext to the screen
        plaintext = decrypt_bytes(gcm, ciphertext.decode())
        print(plaintext)

    except Exception as e:
        print(e)

