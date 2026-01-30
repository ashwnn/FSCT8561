import getpass
import json
import socket
import sys

def request_auth(host: str, port: int, username: str, password: str, otp: str) -> dict:
    payload = json.dumps({
        "username": username,
        "password": password,
        "otp": otp,
    }).encode("utf-8")

    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(payload)
        response = sock.recv(4096)
    return json.loads(response.decode("utf-8"))


def interactive_auth(host: str, port: int) -> None:
    print("Enter credentials when prompted. Blank username exits.")
    while True:
        username = input("Username: ").strip()
        if not username:
            print("Goodbye.")
            break

        password = getpass.getpass("Password: ")
        otp = input("TOTP: ").strip()

        try:
            response = request_auth(host, port, username, password, otp)
        except (ConnectionRefusedError, TimeoutError) as exc:
            print("Unable to reach server:", exc)
            continue
        except json.JSONDecodeError:
            print("Bad response from server.")
            continue

        status = response.get("status", "error")
        message = response.get("message", "No message provided")
        print(f"[{status}] {message}")

def main() -> None:

    host = "127.0.0.1"
    port = 9000

    if len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        try:
            port = int(sys.argv[2])
        except ValueError:
            print("Usage: auth_client.py [host] [port]")
            sys.exit(1)

    interactive_auth(host, port)


if __name__ == "__main__":
    main()
