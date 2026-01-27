import socket

HOST = "127.0.0.1"
PORT = 12345

# Client-side safety limit to avoid sending huge payloads
MAX_LEN = 256

# Display server responses clearly. This reads the server reply and returns it as a clean string.
def recv_response(sock: socket.socket) -> str:
    
    data = sock.recv(1024)
    if not data:
        return ""
    return data.decode("utf-8", errors="replace").strip()

def main():
    # Prompt user for a username
    username = input("Enter username (3-20 chars, alnum/_): ").strip()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
        except Exception as e:
            print(f"Could not connect: {e}")
            return

        print(f"Connected to {HOST}:{PORT}")

        # Send HELLO upon connection
        hello = f"HELLO|{username}"
        s.sendall(hello.encode("utf-8"))

        # Display server responses clearly
        resp = recv_response(s)
        if resp == "":
            print("Server disconnected.")
            return

        print("Server:", resp)

        # If HELLO rejected, stop early (protocol requires HELLO first)
        if not resp.startswith("OK|"):
            print("HELLO rejected. Exiting.")
            return

        # Allow multiple messages per session
        while True:
            text = input("Message (/exit to quit): ")

            # Exit cleanly using EXIT command
            if text.strip().lower() in {"/exit", "exit", "quit"}:
                s.sendall("EXIT|".encode("utf-8"))
                resp = recv_response(s)
                if resp == "":
                    print("Server disconnected.")
                else:
                    print("Server:", resp)
                break

            if text.strip() == "":
                print("Empty message")
                continue

            # Messages exceeding a fixed length (client-side prevention)
            payload = f"MSG|{text}"
            if len(payload) > MAX_LEN:
                print("Your message is too long.")
                continue

            s.sendall(payload.encode("utf-8"))

            # Display server responses clearly
            resp = recv_response(s)
            if resp == "":
                print("Server disconnected.")
                break
            print("Server:", resp)

if __name__ == "__main__":
    main()
