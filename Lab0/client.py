import socket

HOST = "127.0.0.1"
PORT = 12345

message = "Hello from the client"  # message

# create a client socket with IPv4 + TCP
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((HOST, PORT))  # connect to server
    client.sendall(message.encode("utf-8"))  # encode and send the message

    reply = client.recv(1024).decode("utf-8", errors="replace")  # receive up to 1024 bytes
    print("Server replied:", reply)  # server's reply
