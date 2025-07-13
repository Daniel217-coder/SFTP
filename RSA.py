from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from Crypto.PublicKey import RSA as CryptoRSA
from cryptography.hazmat.primitives import serialization

def generate_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def save_key(file_path, key_bytes):
    with open(file_path, 'wb') as f:
        f.write(key_bytes)

def load_key(file_path):
    with open(file_path, 'rb') as f:
        return RSA.import_key(f.read())

def encrypt_with_rsa(public_key, data):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)

def decrypt_with_rsa(private_key, ciphertext):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)

def sign_data(private_key, data_bytes):
    h = SHA256.new(data_bytes)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def verify_signature(public_key, data_bytes, signature):
    h = SHA256.new(data_bytes)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def load_pubkey_from_cert(cert_path):
    """
    Load a public key from an X.509 certificate (.pem).
    """
    with open(cert_path, "rb") as f:
        cert_data = f.read()
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    return cert.public_key()

def cryptography_pubkey_to_pycrypto(crypto_pubkey):
    pem = crypto_pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return CryptoRSA.import_key(pem)