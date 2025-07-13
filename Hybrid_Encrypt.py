from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from RSA import encrypt_with_rsa, decrypt_with_rsa, sign_data, verify_signature
from RSA import load_key
import os

def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    return data[:-data[-1]]

def hybrid_encrypt(input_file, receiver_pubkey_path, sender_privkey_path, output_dir):
    # Generate AES key
    aes_key = get_random_bytes(32)

    # Encrypt file with AES
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher_aes.iv
    with open(input_file, 'rb') as f:
        plaintext = pad(f.read())
    ciphertext = cipher_aes.encrypt(plaintext)

    # Encrypt AES key with receiver's public RSA key
    receiver_pubkey = load_key(receiver_pubkey_path)
    enc_aes_key = encrypt_with_rsa(receiver_pubkey, aes_key)

    # Sign the ciphertext with sender's private key
    sender_privkey = load_key(sender_privkey_path)
    signature = sign_data(sender_privkey, ciphertext)

    # Save output
    base = os.path.basename(input_file)
    with open(os.path.join(output_dir, base + ".enc"), 'wb') as f:
        f.write(iv + ciphertext)
    with open(os.path.join(output_dir, base + ".key.rsa"), 'wb') as f:
        f.write(enc_aes_key)
    with open(os.path.join(output_dir, base + ".sig"), 'wb') as f:
        f.write(signature)

    return True


def hybrid_decrypt(enc_file, enc_key_file, sig_file, sender_pubkey, receiver_privkey_path, output_file):
    # Load data
    with open(enc_file, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()

    with open(enc_key_file, 'rb') as f:
        enc_aes_key = f.read()

    with open(sig_file, 'rb') as f:
        signature = f.read()

    # Decrypt AES key
    receiver_privkey = load_key(receiver_privkey_path)
    aes_key = decrypt_with_rsa(receiver_privkey, enc_aes_key)

    # Decrypt file
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher_aes.decrypt(ciphertext))

    # Verify signature
    # NU mai folosi load_key(sender_pubkey_path) aici!
    if not verify_signature(sender_pubkey, ciphertext, signature):
        raise ValueError("Signature verification failed!")

    with open(output_file, 'wb') as f:
        f.write(plaintext)

    return True
