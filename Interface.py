import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
import json, os, socket

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from RSA import (
    load_key,
    encrypt_with_rsa, decrypt_with_rsa, sign_data, verify_signature,
    load_pubkey_from_cert, cryptography_pubkey_to_pycrypto
)

USER_STORE = "user_store.json"
KEYS_DIR = "keys"
BG_IMAGE = "cyber_ui_background.png"

# ------------------ SEND FILES TO SERVER FUNCTION ------------------
def send_files_to_server(server_ip, port, files):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_ip, port))
            s.sendall(f"{len(files):04}".encode())
            for filepath in files:
                filename = os.path.basename(filepath)
                s.sendall(f"{len(filename):04}".encode())
                s.sendall(filename.encode())
                filesize = os.path.getsize(filepath)
                s.sendall(f"{filesize:016}".encode())
                with open(filepath, "rb") as f:
                    while True:
                        chunk = f.read(4096)
                        if not chunk:
                            break
                        s.sendall(chunk)
            resp = s.recv(2)
            return resp == b"OK"
    except Exception as e:
        print("Send error:", e)
        return False

# ------------------ ENCRYPTION UTILS ------------------
def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    return data[:-data[-1]]

def hybrid_encrypt(input_file, receiver_pubkey_path, sender_privkey_path, output_dir):
    aes_key = get_random_bytes(32)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher_aes.iv
    with open(input_file, 'rb') as f:
        plaintext = pad(f.read())
    ciphertext = cipher_aes.encrypt(plaintext)

    receiver_pubkey = load_key(receiver_pubkey_path)
    enc_aes_key = encrypt_with_rsa(receiver_pubkey, aes_key)

    sender_privkey = load_key(sender_privkey_path)
    signature = sign_data(sender_privkey, ciphertext)

    base = os.path.basename(input_file)
    with open(os.path.join(output_dir, base + ".enc"), 'wb') as f:
        f.write(iv + ciphertext)
    with open(os.path.join(output_dir, base + ".key.rsa"), 'wb') as f:
        f.write(enc_aes_key)
    with open(os.path.join(output_dir, base + ".sig"), 'wb') as f:
        f.write(signature)
    return True

def hybrid_decrypt(enc_file, enc_key_file, sig_file, sender_pubkey, receiver_privkey_path, output_file):
    with open(enc_file, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()
    with open(enc_key_file, 'rb') as f:
        enc_aes_key = f.read()
    with open(sig_file, 'rb') as f:
        signature = f.read()

    receiver_privkey = load_key(receiver_privkey_path)
    aes_key = decrypt_with_rsa(receiver_privkey, enc_aes_key)

    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher_aes.decrypt(ciphertext))

    if not verify_signature(sender_pubkey, ciphertext, signature):
        raise ValueError("Signature verification failed!")

    with open(output_file, 'wb') as f:
        f.write(plaintext)
    return True

def load_users():
    if not os.path.exists(USER_STORE):
        return {}
    with open(USER_STORE) as f:
        return json.load(f)

# ------------------ MAIN CLASS ------------------
class CyberSecureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberSecure File Transfer v2")
        self.root.geometry("1280x720")
        self.root.resizable(False, False)

        bg = Image.open(BG_IMAGE).resize((1280, 720))
        self.bg_image = ImageTk.PhotoImage(bg)
        self.canvas = tk.Canvas(root, width=1280, height=720, highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.canvas.create_image(0, 0, image=self.bg_image, anchor="nw")

        self.users = load_users()
        self.username = tk.StringVar()
        self.recipient = tk.StringVar()
        self.file_path = ""
        self.base_filename = ""

        # ---- BUTOANE SI LAYOUT (dupa cum ai pus tu) ----
        y_start = 120
        spacing = 60
        width = 250

        self.label("Add New User", 1010, y_start - 80)
        self.new_user_var = tk.StringVar()
        self.new_user_entry = tk.Entry(root, textvariable=self.new_user_var, font=("Consolas", 11))
        self.canvas.create_window(1010, y_start - 55, window=self.new_user_entry, width=width)
        self.canvas.create_window(1010, y_start - 25, window=self.create_button("Generate Keypair & Certificate", self.generate_keys), width=width)

        self.label("Select User (Sender)", 1010, y_start)
        self.user_combo = ttk.Combobox(root, values=list(self.users.keys()), textvariable=self.username, style="Custom.TCombobox", font=("Consolas", 11))
        self.canvas.create_window(1010, y_start + 30, window=self.user_combo, width=width)

        self.label("Recipient", 1010, y_start + spacing)
        self.rec_combo = ttk.Combobox(root, values=list(self.users.keys()), textvariable=self.recipient, style="Custom.TCombobox", font=("Consolas", 11))
        self.canvas.create_window(1010, y_start + spacing + 30, window=self.rec_combo, width=width)

        self.canvas.create_window(
            1010, y_start + spacing * 2,
            window=self.create_button("View Certificate Info", self.show_cert_info),
            width=width
        )

        self.canvas.create_window(1010, y_start + spacing * 2 + 40, window=self.create_button("Select File", self.select_file), width=width)
        self.canvas.create_window(1010, y_start + spacing * 3 + 20, window=self.create_button("Encrypt & Sign", self.encrypt_and_sign), width=width)
        self.canvas.create_window(1010, y_start + spacing * 4, window=self.create_button("Auto-Select Encrypted Files", self.select_encrypted_set), width=width)
        self.canvas.create_window(1010, y_start + spacing * 5, window=self.create_button("Decrypt & Verify", self.decrypt_and_verify), width=width)
        self.canvas.create_window(1010, y_start + spacing * 6, window=self.create_button("Send Encrypted Files", self.send_encrypted_files), width=width)

        self.status_label = tk.Label(self.root, text="No file selected", bg="#1a1a2e", fg="cyan", font=("Consolas", 10))
        self.canvas.create_window(1010, y_start + spacing * 7 - 10, window=self.status_label, width=width)

        if self.users:
            first = list(self.users.keys())[0]
            self.username.set(first)
            self.recipient.set(first)

    def label(self, text, x, y):
        self.canvas.create_text(x, y, text=text, fill="white", font=("Consolas", 12))

    def create_button(self, text, command):
        return tk.Button(self.root, text=text, command=command,
                         bg="#6c2bd9", fg="white",
                         font=("Consolas", 11), bd=0, relief="flat",
                         activebackground="#3e1c78", height=1)

    def select_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path = path
            self.status_label.config(text=f"Selected: {os.path.basename(path)}")

    def encrypt_and_sign(self):
        user = self.username.get().strip()
        recipient = self.recipient.get().strip()

        if not user or not recipient or not self.file_path:
            messagebox.showerror("Error", "Make sure all fields and file are selected.")
            return

        if user not in self.users or recipient not in self.users:
            messagebox.showerror("Error", "Invalid user or recipient.")
            return

        try:
            output_dir = os.path.dirname(self.file_path)
            hybrid_encrypt(
                input_file=self.file_path,
                receiver_pubkey_path=self.users[recipient]["public_key"],
                sender_privkey_path=self.users[user]["private_key"],
                output_dir=output_dir
            )
            self.status_label.config(text="File encrypted and signed in same folder.")
            messagebox.showinfo("Success", f"Encrypted and signed files saved in:\n{output_dir}")

        except Exception as e:
            self.status_label.config(text="Encryption failed.")
            messagebox.showerror("Error", str(e))

    def select_encrypted_set(self):
        path = filedialog.askopenfilename(title="Select .enc file")
        if path and path.endswith(".enc"):
            self.base_filename = path[:-4]
            self.enc_file = path
            self.key_file = self.base_filename + ".key.rsa"
            self.sig_file = self.base_filename + ".sig"
            if not all(map(os.path.exists, [self.enc_file, self.key_file, self.sig_file])):
                return messagebox.showerror("Error", "Missing one or more required files.")
            self.status_label.config(text=f"Loaded: {os.path.basename(self.base_filename)}")

    def generate_keys(self):
        name = self.new_user_var.get().strip()
        if not name:
            return messagebox.showerror("Error", "Username cannot be empty.")
        if name in self.users:
            return messagebox.showerror("Error", "Username already exists.")
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        from cryptography import x509
        import datetime

        os.makedirs(KEYS_DIR, exist_ok=True)
        priv_path = os.path.join(KEYS_DIR, f"{name}_priv.pem")
        pub_path = os.path.join(KEYS_DIR, f"{name}_pub.pem")
        cert_path = os.path.join(KEYS_DIR, f"{name}_cert.pem")

        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(priv_path, "wb") as f:
            f.write(priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        pub_key = priv_key.public_key()
        with open(pub_path, "wb") as f:
            f.write(pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(pub_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
            .sign(priv_key, hashes.SHA256())
        )
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        self.users[name] = {
            "public_key": pub_path,
            "private_key": priv_path,
            "certificate": cert_path
        }
        with open(USER_STORE, 'w') as f:
            json.dump(self.users, f, indent=2)
        self.user_combo["values"] = list(self.users.keys())
        self.rec_combo["values"] = list(self.users.keys())
        messagebox.showinfo("Success", f"User '{name}' added with keypair and certificate.")
        self.new_user_var.set("")

    def show_cert_info(self):
        user = self.username.get()
        if not user or not user in self.users:
            return messagebox.showerror("Error", "Please select a valid user.")
        cert_path = self.users[user].get("certificate")
        if not cert_path or not os.path.exists(cert_path):
            return messagebox.showerror("Error", f"Certificate for user '{user}' not found.")
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        with open(cert_path, "rb") as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        serial = cert.serial_number
        issuer = cert.issuer.rfc4514_string()
        text = (
            f"Common Name (CN): {cn}\n"
            f"Serial Number: {serial}\n"
            f"Issuer: {issuer}\n"
            f"Valid From: {not_before}\n"
            f"Valid Until: {not_after}"
        )
        messagebox.showinfo("Certificate Details", text)

    def decrypt_and_verify(self):
        user = self.username.get()
        sender = self.recipient.get()
        if user not in self.users or sender not in self.users:
            return messagebox.showerror("Error", "Invalid user or sender.")
        if not hasattr(self, 'enc_file') or not hasattr(self, 'key_file') or not hasattr(self, 'sig_file'):
            return messagebox.showerror("Error", "Please select encrypted files.")

        sender_cert_path = self.users[sender].get("certificate")
        if not sender_cert_path or not os.path.exists(sender_cert_path):
            return messagebox.showerror("Error", "Sender certificate not found.")

        sender_pubkey_crypto = load_pubkey_from_cert(sender_cert_path)
        sender_pubkey = cryptography_pubkey_to_pycrypto(sender_pubkey_crypto)

        out_file = filedialog.asksaveasfilename(title="Save decrypted output")
        try:
            hybrid_decrypt(
                self.enc_file,
                self.key_file,
                self.sig_file,
                sender_pubkey,
                self.users[user]["private_key"],
                out_file
            )
            messagebox.showinfo("Success", "Decryption and signature verification succeeded.")
        except Exception as e:
            messagebox.showerror("Failed", str(e))

    def send_encrypted_files(self):
        import tkinter.simpledialog
        server_ip = tk.simpledialog.askstring("Server IP", "Enter server IP address (default 127.0.0.1):") or "127.0.0.1"
        port = 5001
        if not hasattr(self, 'enc_file') or not hasattr(self, 'key_file') or not hasattr(self, 'sig_file'):
            return messagebox.showerror("Error", "Select encrypted files first (Auto-Select Encrypted Files)!")
        files = [self.enc_file, self.key_file, self.sig_file]
        ok = send_files_to_server(server_ip, port, files)
        if ok:
            messagebox.showinfo("Success", f"Files sent to {server_ip}:{port}!")
        else:
            messagebox.showerror("Error", f"Failed to send files to {server_ip}:{port}.")

if __name__ == '__main__':
    root = tk.Tk()
    app = CyberSecureApp(root)
    root.mainloop()
