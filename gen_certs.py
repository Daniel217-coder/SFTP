from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography import x509
import datetime
import os

def generate_user_cert(username, out_dir="keys", key_size=2048):
    os.makedirs(out_dir, exist_ok=True)
    priv_path = os.path.join(out_dir, f"{username}_priv.pem")
    pub_path = os.path.join(out_dir, f"{username}_pub.pem")
    cert_path = os.path.join(out_dir, f"{username}_cert.pem")

    # 1. Generează cheia privată RSA
    priv_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    # 2. Salvează cheia privată
    with open(priv_path, "wb") as f:
        f.write(priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # 3. Salvează cheia publică
    pub_key = priv_key.public_key()
    with open(pub_path, "wb") as f:
        f.write(pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    # 4. Creează un certificat self-signed
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username)
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=366))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(username)]),
            critical=False,
        )
        .sign(priv_key, hashes.SHA256())
    )

    # 5. Salvează certificatul
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"User: {username}")
    print(f"  Private key: {priv_path}")
    print(f"  Public key:  {pub_path}")
    print(f"  Certificate: {cert_path}\n")

# ===== USAGE =====
users = ["alice", "bob"]  # Poți adăuga aici orice user vrei
for user in users:
    generate_user_cert(user)
