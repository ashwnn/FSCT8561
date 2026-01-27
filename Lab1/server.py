import socket

HOST = "127.0.0.1"
PORT = 12345

# Make sure messages don't exceed a fixed length
MAX_LEN = 256

# Only these commands are valid
ALLOWED = {"HELLO", "MSG", "EXIT"}

def handle_message(raw: str, state: dict) -> str:
    """
    - Enforce COMMAND|DATA format, and support HELLO/MSG/EXIT.
    - Reject any message before a valid HELLO.
    - Validate all incoming messages.
    - Handle malformed input without crashing (by returning ERROR|reason).
    - Maintain session state (username, connection status).
    """

    # Handle empty messages
    if raw is None:
        return "ERROR|Empty message"

    msg = raw.strip()
    if msg == "":
        return "ERROR|Empty message"

    # Enforce fixed max length
    if len(msg) > MAX_LEN:
        return "ERROR|Message too long"

    # Require COMMAND|DATA
    if "|" not in msg:
        return "ERROR|Invalid format, expected COMMAND|DATA"

    # Split only once to allow 'DATA' to contain '|' characters after the first separator
    command, data = msg.split("|", 1)
    command = command.strip().upper()
    data = data.strip()

    # Reject unknown commands
    if command not in ALLOWED:
        return "ERROR|Unknown command"

    # Reject any message before valid HELLO
    if not state.get("authed", False) and command != "HELLO":
        return "ERROR|Must send HELLO first"

    # HELLO: establish identity and session state
    if command == "HELLO":
        # Do not allow re-HELLO once authenticated
        if state.get("authed", False):
            return "ERROR|Already introduced"

        # Validation
        if data == "":
            return "ERROR|Username required"

        # Basic username validation for safety and clarity
        if not (3 <= len(data) <= 20):
            return "ERROR|Username must be 3-20 chars"
        if not all(ch.isalnum() or ch == "_" for ch in data):
            return "ERROR|Username must be alphanumeric or underscore"

        # Maintain session state
        state["authed"] = True
        state["username"] = data
        return "OK|"

    # MSG: accept chat messages only after HELLO
    if command == "MSG":
        if data == "":
            return "ERROR|Message text required"

        # Log message content with username
        print(f"[CHAT] {state.get('username')}: {data}")
        return "OK|"

    # EXIT: clean disconnect request
    if command == "EXIT":
        # Clean exit using EXIT command
        state["exit_requested"] = True
        return "OK|"

    return "ERROR|Unhandled command"

def log_error(addr, reason: str) -> None:
    # Log errors
    print(f"[ERROR] {addr}: {reason}")

def main():
    # Setup TCP Server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(1)
        print(f"[INFO] Server listening on {HOST}:{PORT}")

        # Server stays up and can accept new connections (not one-and-done)
        while True:
            conn, addr = server.accept()
            with conn:
                # Log connections
                print(f"[INFO] Connected by {addr}")

                # Maintain session state for this client
                state = {"authed": False, "username": None, "exit_requested": False}

                try:
                    # Persistent connection (multiple messages per client)
                    while True:
                        data = conn.recv(1024)

                        # Handle unexpected client disconnect
                        if not data:
                            print(f"[WARN] Client disconnected unexpectedly: {addr}")
                            break

                        raw = data.decode("utf-8", errors="replace")
                        response = handle_message(raw, state)

                        # Log errors 
                        if response.startswith("ERROR|"):
                            log_error(addr, response.split("|", 1)[1])

                        # Server responds with OK| or ERROR|reason
                        conn.sendall(response.encode("utf-8"))

                        # Clean disconnect when EXIT received
                        if state.get("exit_requested"):
                            print(f"[INFO] Client requested exit: {state.get('username')} @ {addr}")
                            break

                # Malformed inputs should not crash the server
                except Exception as e:
                    log_error(addr, f"Unhandled exception: {type(e).__name__}: {e}")

                finally:
                    # Log disconnections
                    print(f"[INFO] Disconnected: {addr}")

if __name__ == "__main__":
    main()
