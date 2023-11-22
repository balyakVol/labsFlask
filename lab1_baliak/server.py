import socket
from datetime import datetime
import time

HOST = "127.0.0.1"
PORT = 25050

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((HOST, PORT))
sock.listen()
conn, addr = sock.accept()
with conn:
    print(f"Connected by {addr}")
    while True:
        data = conn.recv(1024)
        if not data:
            break

        print("Timeout is on...")
        time.sleep(5)
        print("Timeout is off...")
        
        conn.sendall(data)
        print(f"\t[Message] - {data.decode()}")
        print(f"\t[Time] - {datetime.now()}")

conn.close()
sock.close()
