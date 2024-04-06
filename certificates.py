import os
import random
import socket
import ipaddress
import ssl
import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization



def create_private_key(name):
    """
    Creates private key for TLS configs.

    Parameters:
      - name: string of the client's name

    Returns:
      - ecdsa.PrivateKey of the new private key
    """
    try:
        # Generate new private key based on the elliptic curve P384
        key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        key_bytes = key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())

        # Create key file
        with open(f"{name}.key", "wb") as key_file:
            key_file.write(key_bytes)
    except Exception as e:
        raise Exception(f"Error creating private key: {e}")

    return key


def create_cert_pool():
    """
    Creates pool of known X509 certificates.

    Returns:
      - string containing known client certificates
    """
    try:
        # Get files in cert directory
        cert_dir = "./certs"
        cert_pool = ""
        for filename in os.listdir(cert_dir):
            with open(os.path.join(cert_dir, filename), "rb") as cert_file:
                cert_pool += cert_file.read().decode("ascii")
    except Exception as e:
        raise Exception(f"Error creating cert pool: {e}")    

    return cert_pool


def create_self_certificate(name):
    """
    Creates self-signed X509 certificate based on name.

    Parameters:
      - name: string of the client's name

    Returns:
      - bytes of the new certificate
    """
    # Move old certificate & keys to other files
    if os.path.isfile(name + ".key") and os.path.isfile(name + ".crt"):
        os.rename(name + ".key", "old_" + name + ".key")
        os.rename(name + ".crt", "old_" + name + ".crt")

    try:
        # Create private key for certificate
        key = create_private_key(name)

        # Ping google to get local ip address
        connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        connection.connect(("8.8.8.8", 80))
        local_ip = connection.getsockname()[0]
        connection.close()

        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        
        # Create template for creating new X509 certificates
        template = x509.CertificateBuilder()
        template = template.subject_name(subject)
        template = template.issuer_name(issuer)
        template = template.add_extension(x509.SubjectAlternativeName([
            x509.DNSName("*"),
            x509.IPAddress(ipaddress.ip_address(local_ip)),
            x509.IPAddress(ipaddress.ip_address("10.0.0.3")),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")), # for testing
        ]), critical=False)
        template = template.serial_number(x509.random_serial_number())
        template = template.not_valid_before(datetime.datetime.utcnow())
        template = template.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))  # 1 year
        template = template.public_key(key.public_key())

        # Create new certificate based on template & new key
        new_cert = template.sign(key, hashes.SHA256(), default_backend())
        
        # Create PEM block for new certificate
        cert_pem = new_cert.public_bytes(serialization.Encoding.PEM)

        # Create key certificate file
        with open(name + ".crt", "wb") as cert_file:
            cert_file.write(cert_pem)

    except Exception as e:
        raise Exception(f"Error creating certificate: {e}")

    return cert_pem

def create_tls_config(crt_path, key_path, skip_verify, listener):
    """
    Creates a new TLS config for senders & receivers.
    Allows clients to send their own certificates & verify
    other certificates.

    Parameters:
      - crt_path: string of the certificate file path
      - key_path: string of the key file path
      - skip_verify: bool for whether to skip certificate verification
      - listener: bool for whether certificate is for senders or receivers

    Returns:
      - tls context of new TLS config
    """

    # Create pool of known certificates
    pool = create_cert_pool()
    try:
        if skip_verify and listener:
            # Return certificate for new friend listeners
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER, ssl.OP_SINGLE_ECDH_USE)
            context.options = ssl.OP_NO_TLSv1_3
            context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384')
            context.verify_mode = ssl.CERT_NONE
            context.load_cert_chain(crt_path, key_path)
            return context

        if skip_verify and not listener:
            # Return certificate for new friend senders
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT, ssl.OP_SINGLE_ECDH_USE)
            context.options = ssl.OP_NO_TLSv1_3
            context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384')
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.load_cert_chain(crt_path, key_path)
            return context
        
        if listener:
            # Return certificate for receivers
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER, ssl.OP_SINGLE_ECDH_USE)
            context.options = ssl.OP_NO_TLSv1_3
            context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384')
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_cert_chain(crt_path, key_path)
            context.load_verify_locations(cadata=pool)
            return context

        else:
            # Return certificate for senders
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT, ssl.OP_SINGLE_ECDH_USE)
            context.options = ssl.OP_NO_TLSv1_3
            context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384')
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_cert_chain(crt_path, key_path)
            context.load_verify_locations(cadata=pool)
            return context

    except Exception as e:
        raise Exception(f"Error creating TLS context: {e}")