import os
import json
import struct
import socket
from encryption import *
from certificates import create_tls_config


def handle_send_message(connection, messages):
    """
    Uses passed connection to send text messages to another client

    Parameters:
      - connection: socket.socket to another client
      - messages: list of previously sent messages
    """
    # Get message to send
    message = input("Enter message: ")

    # Check if user wants to quit
    if message.lower() == "/quit":
        return None

    # Convert message into JSON object
    try:
        json_data = json.dumps({"text": message, "file": None, "certificate": None}).encode()
    except Exception as e:
        raise Exception(f"Failed to create message: {e}")

    # Convert 32-bit size into 4 separate bytes for sending
    size = len(json_data)
    size_buffer = struct.pack("!I", size)

    # Send size & message to client
    try:
        connection.sendall(size_buffer)
        connection.sendall(json_data)
    except Exception as e:
        raise Exception(f"Failed to send message: {e}")

    # Append message to stored messages
    messages.append(message)

    print("Sent.")


def handle_send_file(connection, messages):
    """
    Uses passed connection to send files to another client

    Parameters:
      - connection: socket-like object for communicating with another client
      - messages: list of previously sent messages
    """
    # Get path to file for sending
    path = input("Enter file path: ")

    # Check that file exists
    try:
        info = os.stat(path)
    except Exception as e:
        raise Exception(f"File {path} does not exist: {e}")

    # Read file data
    try:
        with open(path, "rb") as file:
            file_data = file.read()
    except Exception as e:
        raise Exception(f"Error reading file: {e}")

    # Convert file data into JSON object
    try:
        json_data = json.dumps({"text": os.path.basename(path), "file": base64.b64encode(file_data).decode(), "certificate": None})
    except Exception as e:
        raise Exception(f"Failed to create message: {e}")

    # Convert 32-bit size into 4 separate bytes for sending
    size = len(json_data)
    size_buffer = struct.pack("!I", size)

    # Send size & file to client
    try:
        connection.sendall(size_buffer)
        connection.sendall(json_data.encode())
    except Exception as e:
        raise Exception(f"Failed to send message: {e}")

    # Append message to stored messages
    messages.append(os.path.basename(path))

    print("Sent.")



def handle_send_revoked_cert(connection):
    """
    Uses passed connection to revoke old certificate

    Parameters:
      - connection: socket-like object to another client
    """
    # Get path to newly generated certificate
    new_cert_path = input("New cert path: ")

    # Read certificate file
    try:
        with open(new_cert_path, "rb") as file:
            certificate = file.read()
    except Exception as e:
        raise Exception(f"Error reading file: {e}")

    # Convert certificate file into JSON object
    try:
        json_data = json.dumps({"text": None, "file": None, "certificate": base64.b64encode(certificate).decode()})
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
        raise Exception(f"Failed to send message: {e}")

    print("Sent.")


#def create_sender(name, port):
def create_sender(crt_path, key_path, destination):
    """
    Creates TLS sender for sending messages to another client.

    Parameters:
      - name: string of client's name
      - destination: string of destination client's address

    Returns:
      - *ssl.SSLSocket to another client
    """
    host = destination
    port = 8081

    # Create TLS context for a sender based on named client
    try:
        context = create_tls_config(crt_path, key_path, False, False)
    except Exception as e:
        raise Exception(f"Error creating context: {e}")

    # Attempt to connect to other client
    #connection = None
    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        secure_connection = context.wrap_socket(connection, server_side=False, server_hostname=host)
        secure_connection.connect((host, port))
    except Exception as e:
        raise Exception(f"Error during TLS connection: {e}")

    # Get connected peers    
    try:
        peers = secure_connection.getpeercert()['subject']
    except Exception as e:
        secure_connection.close()
        raise Exception(f"No peers connected: {e}")

    # Get name of most recent connection
    peer_name = peers[-1][0][1]
    print("\nConnected to:", peer_name)

    return secure_connection


