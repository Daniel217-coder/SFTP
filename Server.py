import socket
import os
import datetime

# Salvează în directorul curent
RECEIVE_DIR = os.path.join(os.path.expanduser("~"), "Desktop", "Proiect Vineri", "received_files")
os.makedirs(RECEIVE_DIR, exist_ok=True)
HOST = '0.0.0.0'
PORT = 5001

def log(msg):
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)

def receive_all(conn, length):
    data = b""
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Socket connection broken")
        data += chunk
    return data

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    log(f"🟢 Server started! Waiting for connections on port {PORT} ...")
    while True:
        log("🔄 Waiting for new client connection ...")
        conn, addr = s.accept()
        log(f"🌐 Connected by {addr}")
        try:
            num_files_raw = receive_all(conn, 4)
            num_files = int(num_files_raw.decode())
            log(f"📦 Will receive {num_files} file(s)")
            for i in range(num_files):
                log(f"⬇️ Receiving file #{i+1}")
                name_len_raw = receive_all(conn, 4)
                name_len = int(name_len_raw.decode())
                filename = receive_all(conn, name_len).decode()
                log(f"  🔹 Filename: {filename}")
                filesize_raw = receive_all(conn, 16)
                filesize = int(filesize_raw.decode())
                log(f"  📏 Size: {filesize} bytes")
                with open(os.path.join(RECEIVE_DIR, filename), "wb") as f:
                    bytes_read = 0
                    while bytes_read < filesize:
                        chunk = conn.recv(min(4096, filesize - bytes_read))
                        if not chunk:
                            break
                        f.write(chunk)
                        bytes_read += len(chunk)
                        if filesize > 0:
                            pct = int(bytes_read * 100 / filesize)
                            log(f"    ...{pct}% received",)
                log(f"✅ File received: {filename} ({filesize} bytes)")
            conn.sendall(b"OK")
            log(f"🏁 All files received from {addr}. Waiting for new connections.")
        except Exception as e:
            log(f"[!] Error: {e}")
        finally:
            conn.close()
            log(f"🔒 Connection closed.\n{'-'*40}")
