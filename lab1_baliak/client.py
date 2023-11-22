import socket

HOST = "127.0.0.1"
PORT = 25050

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

while input != "":
    data = input("Enter something to send: ")

    sock.sendall(data.encode())
    data = sock.recv(1024)

    print(f"Received {data!r}")
