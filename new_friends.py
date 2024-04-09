import random
import os
import socket
import json
import struct
import base64
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from zeroconf_config import *
from certificates import create_tls_config


def create_nonce():
    start = 100000
    diff = 899999
    offset = random.randint(0, diff)
    nonce = start + offset

    return nonce


def create_peer_cert_file(peer_name, peer_cert):
    if os.path.exists("./certs/" + peer_name + ".crt"):
        print(f"./certs/" + peer_name + ".crt already exists")
        return 

    try:
        cert_pem = peer_cert.public_bytes(serialization.Encoding.PEM)
        with open("./certs/" + peer_name + ".crt", "wb") as cert_file:
            cert_file.write(cert_pem)
    except Exception as e:
        raise Exception(f"Failed to create peer cert file: {e}")


def handle_receive_nonce_cert(connection, nonce):
    """
    Handles a single connection of a client.
    Allows the connected client to send messages and files.
    All messages are stored and encryptedf upon disconnection.

    Parameters:
        connection: The connection object of the connected client.
        peer_name (str): The name of the connected client.
        password (str): The encryption password.

    Raises:
        Exception: If any error occurs during execution.
    """

    try:
        # Read size of message as 4 bytes
        size_buffer = connection.recv(4)
        if not size_buffer:
            return

        # Decode length stored in 4 separate bytes into single 32-bit integer
        size = int.from_bytes(size_buffer, byteorder='big')

        # Read bytes based on decoded size
        msg_buffer = connection.recv(size)
        if not msg_buffer:
            return

        # Convert msg_buffer into JSON object
        try:
            message = json.loads(msg_buffer)
        except Exception as e:
            raise Exception(f"could not load JSON object: {e}")

        if message['certificate']:
            # Handle certificate
            peer = base64.b64decode(message['certificate'])
            passed_nonce = int(message['text'])
        else:
            raise Exception(f"Failed to recieve cert")

        # load cert as pem
        try:
            peer_cert = x509.load_pem_x509_certificate(peer)
            peer_name = peer_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value  
        except Exception as e:
            raise Exception(f"Failed to load cert: {e}")

        if passed_nonce != nonce:
            return Exception(peer_name + " sent an invalid nonce")
        
    except Exception as e:
        print(f"Error handle receive nonce cert: {e}")
        return e

    return peer_cert

def handle_send_nonce_cert(connection, cert_path):
    """
    Uses passed connection to revoke old certificate

    Parameters:
      - connection: socket-like object to another client
      - cert_path: path to cert file

    Raises:
        Exception: If any error occurs during execution.
    """

    client_nonce  = input("Enter other client's nonce: ")

    # Read certificate file
    try:
        with open(cert_path, "rb") as file:
            certificate = file.read()
    except Exception as e:
        raise Exception(f"Error reading cert file: {e}")
        

    # Convert certificate file into JSON object
    try:
        json_data = json.dumps({"text": client_nonce, "file": None, "certificate": base64.b64encode(certificate).decode()})
    except Exception as e:
        raise Exception(f"Failed to create message: {e}")

    # Convert 32-bit size into 4 separate bytes for sending
    size = len(json_data)
    size_buffer = struct.pack("!I", size)

    # Send size & new certificate
    try:
        connection.sendall(size_buffer)
        connection.sendall(json_data.encode())
    except Exception as e:
        raise Exception(f"Failed to send certificate. {e}")


def create_new_friend_listener(crt_path, key_path, nonce):
    """
    Listen for a new friend request.

    Parameters:
        crt_path (str): Path to user's certificate.
        key_path (str): Path to user's key.
        nonce (int): Expected value from other clients.

    Raises:
        Exception: If any error occurs during execution.
    """
    # Create TLS config for named client
    try:
        context = create_tls_config(crt_path, key_path, True, True)
    except Exception as e:
        raise Exception(f"Error creating tls context: {e}")


    # Start listening on port 8081
    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("", 8081))
        print("Listening on 8081")
        listener.listen()
    except Exception as e:
        raise Exception(f"Error creating listener: {e}")

    try:
        service = create_zeroconf_service()
    except Exception as e:
        raise Exception(f"Error creating zeroconf service: {e}")

    try:
        # Accept new connection
        try:
            connection, address = listener.accept()
            tls_conn = context.wrap_socket(connection, server_side=True)
        except Exception as e:
            raise Exception(f"Error creating tls connection: {e}")       

        # Validate received nonce and get peer's cert
        try:
            peer_cert = handle_receive_nonce_cert(tls_conn, nonce)
            peer_name = peer_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except Exception as e:
            raise Exception(e)  

        # Send peer's expected nonce and own cert
        try:
            handle_send_nonce_cert(tls_conn, crt_path)
        except Exception as e:
            raise Exception(e)  

        # Create new certificate file for peer
        try:
            print("Creating cert file")
            create_peer_cert_file(peer_name, peer_cert)
        except Exception as e:
            raise Exception(e)  
    finally:
        print("Connection closed")
        service.close()
        tls_conn.close()
        connection.close()
        listener.close()

            

def create_new_friend_sender(crt_path, key_path, destination, nonce):
    """
    Sends new friend request.

    Parameters:
        crt_path (str): Path to user's certificate.
        key_path (str): Path to user's key.
        destination (str): Friend's address.
        nonce (int): Expected value from other clients.

    Returns:
        Exception: If any occurred during execution.
    """
    host = destination
    port = 8081

    # Create TLS config for a sender based on named client
    try:
        context = create_tls_config(crt_path, key_path, True, False)
    except Exception as e:
        raise Exception(f"Error creating context: {e}")

    try:
        # Attempt to connect to other client
        try:
            connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tls_conn = context.wrap_socket(connection, server_side=False)
            tls_conn.connect((host, port))
        except Exception as e:
            raise Exception(f"Error during TLS connection: {e}")

        # Send peer's expected nonce and own cert
        try:
            handle_send_nonce_cert(tls_conn, crt_path)
        except Exception as e:
            raise Exception(e)  

        # Validate received nonce and get peer's cert
        try:
            peer_cert = handle_receive_nonce_cert(tls_conn, nonce)
            peer_name = peer_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except Exception as e:
            raise Exception(e)  

        # Create new certificate file for peer
        try:
            print("Creating cert file")
            create_peer_cert_file(peer_name, peer_cert)
        except Exception as e:
            raise Exception(e)  
    finally:
        print("Connection closed")
        tls_conn.close()
        connection.close()

