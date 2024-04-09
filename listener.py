import os
import json
import datetime
import socket
import base64
from encryption import *
from zeroconf_config import *
from certificates import create_tls_config
from cryptography import x509
from cryptography.hazmat.primitives import serialization


def handle_new_client(connection, peer_name, password):
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
    messages = []

    while True:
        try:
            # Read size of message as 4 bytes
            size_buffer = connection.recv(4)
            if not size_buffer:
                # Encrypt session messages if connection is closed
                print(f"Connection closed")
                encrypt_messages(password, f"received_{peer_name}_{str(datetime.datetime.now())}", messages)
                connection.close()
                break              
            
            # Decode length stored in 4 separate bytes into single 32-bit integer
            size = int.from_bytes(size_buffer, byteorder='big')

            # Read bytes based on decoded size
            msg_buffer = connection.recv(size)
            if not msg_buffer:
                connection.close()
                break

            # Convert msg_buffer into JSON object
            try:
                message = json.loads(msg_buffer)
            except Exception as e:
                    raise Exception(f"could not load JSON object: {e}")

            if message['certificate']:
                # Convert new certificate to PEM block
                try:
                    message_cert = base64.b64decode(message['certificate'])
                    cert = x509.load_pem_x509_certificate(message_cert)
                except Exception as e:
                    raise Exception(f"could not load certificate: {e}")

                # Ensure old certificate name and new certificate name match
                if peer_name != cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value:
                    raise Exception("client tried to revoke a certificate under a different name")

                # Handle certificate revocation
                try:
                    with open(f"./certs/{peer_name}.crt", "wb") as f:
                        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
                        f.write(cert_pem)
                except Exception as e:
                    raise Exception(f"could not write new certificate to file: {e}")

                print(f"{peer_name} sent new certificate: {peer_name}.crt")
                print("Please restart your application to configure the new certificate")

            elif message['file']:
                # Append message to stored messages
                messages.append(f"{peer_name}: {message['text']}")
                # Handle sending of files
                try:
                    with open(f"copy_{message['text']}", "wb") as f:
                        f.write(base64.b64decode(message['file']))
                except Exception as e:
                    raise Exception(f"could not save file: {e}")
                print(f"{peer_name}: Sent file called {message['text']}")

            else:
                # Append message to stored messages
                messages.append(f"{peer_name}: {message['text']}")
                # Handle text messages
                print(f"{peer_name}: {message['text']}")
            
        except Exception as e:
            raise Exception(f"Error handle new client: {e}")


def create_listener(cert_path, key_path, password):
    """
    Creates TLS listener for accepting new clients.

    Parameters:
      - cert_path: path to client's certificate
      - key_path: path to client's key
      - password: encryption password as a string

    Raises:
        Exception: If any error occurs during execution.
    """
    # Create TLS config for client
    try:
        context = create_tls_config(cert_path, key_path, False, True)
    except Exception as e:
        raise Exception(f"Error creating tls context: {e}")

    # Start listening on port 8081
    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("", 8081))
        listener.listen(5)
        print("Listening on 8081")
    except Exception as e:
        raise Exception(f"Error creating listener: {e}")

    # Create zeroconf service for mDNS
    try:
        service = create_zeroconf_service()
    except Exception as e:
        raise Exception(f"Error creating zeroconf service: {e}")

    try:
        while True:
            # Accept new connections
            try:
                connection, address = listener.accept()
                tls_conn = context.wrap_socket(connection, server_side=True)
            except Exception as e:
                raise Exception(f"Error creating tls connection: {e}")

            # Get connected peers
            try:
                peers = tls_conn.getpeercert()['subject']
            except Exception as e:
                tls_conn.close()
                raise Exception(f"Could not get peer cert: {e}")

            # Get name of most recent connection
            peer_name = peers[-1][0][1]
            print("Connected to:", peer_name)

            # Handle messages from newest client
            handle_new_client(tls_conn, peer_name, password)
    except KeyboardInterrupt:
        pass
    finally:
        service.close()
        listener.close()

