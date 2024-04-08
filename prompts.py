import os
from listener import *
from sender import *
from encryption import *
from certificates import *
from new_friends import *
from io import StringIO
import datetime
from zeroconf_config import *

def prompt_user_new_cert():
    """
    Asks the user for their name & generates a new X509 certificate
    based on their name.
    """
    # Get name of client without newline characters
    line_reader = StringIO(input("Enter name: "))
    name = line_reader.readline().strip()

    # Create new self-signed certificate based on name
    try:
        create_self_certificate(name)
    except Exception as e:
        print(f"prompt_user_new_cert: {e}")


def prompt_create_listener():
    """
    Asks the user for their name & encryption password.
    Then calls createListener to create a new TLS listener.
    """

    line_reader = StringIO(input("Path to cert file: "))
    cert_path = line_reader.readline().strip()

    if not os.path.exists(cert_path):
        print(f"prompt_create_listener: {cert_path} does not exist")
        return

    line_reader = StringIO(input("Path to key file: "))
    key_path = line_reader.readline().strip()

    if not os.path.exists(key_path):
        print(f"prompt_create_listener: {key_path} does not exist")
        return

    line_reader = StringIO(input("Enter encryption password: "))
    password = line_reader.readline().strip()

    try:
        create_listener(cert_path, key_path, password)
    except Exception as e:
        print(f"prompt_create_listener: {e}")


def prompt_create_sender():
    """
    Asks the user for their name & a destination.
    Then creates a connection to the receiver & allows the user to send information.
    """

    # Get path to user's certificate
    line_reader = StringIO(input("Path to cert file: "))
    cert_path = line_reader.readline().strip()

    if not os.path.exists(cert_path):
        print(f"prompt_create_sender: {cert_path} does not exist")
        return

    # Get path to user's key
    line_reader = StringIO(input("Path to key file: "))
    key_path = line_reader.readline().strip()

    if not os.path.exists(key_path):
        print(f"prompt_create_sender: {key_path} does not exist")
        return

    # List all TLS services running on the local network
    list_zeroconf_services()

    # Get address of receiver without newline characters
    line_reader = StringIO(input("Enter destination: "))
    destination = line_reader.readline().strip()

    # Get a TLS connection to the receiver
    try:
        connection = create_sender(cert_path, key_path, destination)
    except Exception as e:
        print(f"prompt_create_sender: {e}")
        return

    messages = []

    # Endlessly loop until user enters /quit
    while True:
        # Print sending options to the user & ask which mode they want
        line_reader = StringIO(input("\n1. Send message\n2. Send file\n3. Quit\nEnter mode: "))

        mode = line_reader.readline().strip()

        try:
            if mode == "1":
                # Handle sending of text messages to the receiver
                handle_send_message(connection, messages)
            elif mode == "2":
                # Handle sending of files to the receiver
                    handle_send_file(connection, messages)
            elif mode == "3":
                # Quit program
                # Get encryption password
                line_reader = StringIO(input("Enter encryption password: "))
                password = line_reader.readline().strip()
                # Encrypt sent files
                encrypt_messages(password, f"sent_{str(datetime.datetime.now())}", messages)
                return
            else:
                print("invalid mode input.")
        except Exception as e:
            print(f"PromptCreateSender: {e}")
            return


def prompt_revoke_certificate():
    # Get path to user's certificate
    line_reader = StringIO(input("Path to old cert file: "))
    cert_path = line_reader.readline().strip()

    if not os.path.exists(cert_path):
        print(f"prompt_revoke_certificate: {cert_path} does not exist")
        return

    # Get path to user's key
    line_reader = StringIO(input("Path to old key file: "))
    key_path = line_reader.readline().strip()

    if not os.path.exists(key_path):
        print(f"prompt_revoke_certificate: {key_path} does not exist")
        return

    # List all TLS services running on the local network
    list_zeroconf_services()

    # Get address of receiver without newline characters
    line_reader = StringIO(input("Enter destination: "))
    destination = line_reader.readline().strip()

    try:
        connection = create_sender(cert_path, key_path, destination)
    except Exception as e:
        print(f"prompt_revoke_certificate: {e}")
        return

    # Handle sending of revoked certificate to the receiver
    try:
        handle_send_revoked_cert(connection)
    except Exception as e:
        print(f"prompt_revoke_certificate: {e}")
        return


def prompt_read_past_messages():
    # Get encryption password without newline characters
    line_reader = StringIO(input("Enter encryption password: "))
    password = line_reader.readline().strip()

    # Read passed session files in the hist directory
    try:
        files = os.listdir("./hist")
    except:
        print("prompt_read_past_messages: missing hist directory")
        return

    # Print list of passed sessions to the user
    for i, file in enumerate(files):
        print(f"{i+1}. {file}")

    # Get session file number from the user
    line_reader = StringIO(input("Enter file #: "))
    file_number = int(line_reader.readline().strip())

    # Validate file number is within range
    if file_number < 1 or file_number > len(files):
        print("prompt_read_past_messages: file number out of range")
        return

    # Decrypt the passed session file & print it to the screen
    try:
        decrypt_file(password, f"./hist/{files[file_number-1]}")
    except Exception as e:
        print(f"prompt_read_past_messages: {e}")
        return



def prompt_accept_new_friends():
    # Get path to user's certificate
    line_reader = StringIO(input("Path to cert file: "))
    cert_path = line_reader.readline().strip()

    if not os.path.exists(cert_path):
        print(f"prompt_accept_new_friends: {cert_path} does not exist")
        return

    # Get path to user's key
    line_reader = StringIO(input("Path to key file: "))
    key_path = line_reader.readline().strip()

    if not os.path.exists(key_path):
        print(f"prompt_accept_new_friends: {key_path} does not exist")
        return

    # Create nonce you expect new friends to send
    nonce = create_nonce()
    print("\nYour Nonce:", nonce)

    # Create listener
    try:
        create_new_friend_listener(cert_path, key_path, nonce)
    except Exception as e:
        print(f"prompt_accept_new_friends: {e}")
        return


def prompt_send_new_friend():
    """
    Allows user to send their certificate to a friend.
    Both parties must verify with a nonce.
    """
    # Get path to user's certificate
    line_reader = StringIO(input("Path to cert file: "))
    cert_path = line_reader.readline().strip()

    if not os.path.exists(cert_path):
        print(f"prompt_send_new_friend: {cert_path} does not exist")
        return

    # Get path to user's key
    line_reader = StringIO(input("Path to key file: "))
    key_path = line_reader.readline().strip()

    if not os.path.exists(key_path):
        print(f"prompt_send_new_friend: {key_path} does not exist")
        return

    # Create nonce you expect new friends to send
    nonce = create_nonce()
    print(f"Your Nonce: {nonce}")

    # List all TLS services running on the local network
    list_zeroconf_services()

    # Get address of receiver without newline characters
    line_reader = StringIO(input("Enter destination: "))
    destination = line_reader.readline().strip()

    # Create a sender to connect to new friend
    try:
        create_new_friend_sender(cert_path, key_path, destination, nonce)
    except Exception as e:
        print(f"prompt_send_new_friend: {e}")

