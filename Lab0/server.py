import socket

HOST = "127.0.0.1"
PORT = 12345

# initialize IPv4 + TCP socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((HOST, PORT))
    server.listen(1)  # allow up to 1 client
    print(f"Server listening on {HOST}:{PORT}")

    conn, addr = server.accept()  # block until client connects, get a new socket
    with conn:  # ensure socket is closed properly
        print("Connected by", addr)  # view client address
        msg = conn.recv(1024).decode("utf-8", errors="replace")  # receive up to 1024 bytes
        print("Client says:", msg)

        reply = "Message received by server"
        conn.sendall(reply.encode("utf-8"))  # encode reply and send back to client
