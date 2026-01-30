import hashlib
import hmac
import json
import logging
import secrets
import socket
import threading
import time

import pyotp
import qrcode
from typing import Optional

HOST = "0.0.0.0"
PORT = 9000
MAX_FAILED_ATTEMPTS = 5
LOCK_DURATION = 30  # seconds

USER_DB = {}

def render_qr(data: str, label: Optional[str] = None) -> None:
    qr = qrcode.QRCode(border=1, box_size=1)
    qr.add_data(data)
    qr.make(fit=True)
    if label:
        print(label)
    qr.print_ascii(invert=True)


def hash_password(password: str, salt: str) -> str:
    # per user salt + sha256
    payload = f"{salt}{password}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def register_user(username: str, raw_password: str) -> None:
    salt = secrets.token_hex(16) # 32 hex chars = 16 bytes
    otp_secret = pyotp.random_base32()
    USER_DB[username] = {
        "salt": salt,
        "password_hash": hash_password(raw_password, salt),
        "otp_secret": otp_secret,
        "failed_attempts": 0,
        "locked_until": 0.0,
    }

    uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(
        name=username, issuer_name="Lab 3"
    ) # 
    logging.info("Seeded account: %s (password=%s)", username, raw_password)
    logging.info("Provisioning URI for %s: %s", username, uri)
    print(f"\nScan this QR to add {username} to a TOTP app:")
    render_qr(uri, f"Provisioning URI for {username}:\n{uri}\n")

def initialize_users() -> None:
    register_user("student", "password")


def verify_password(record: dict, password: str) -> bool:
    return hmac.compare_digest(record["password_hash"], hash_password(password, record["salt"]))


def verify_totp(record: dict, token: str) -> bool:
    totp = pyotp.TOTP(record["otp_secret"])
    return bool(totp.verify(token))

def send_response(conn: socket.socket, status: str, message: str) -> None:
    payload = json.dumps({"status": status, "message": message}).encode("utf-8")
    conn.sendall(payload)

def handle_failed_attempt(record: dict) -> str:
    record["failed_attempts"] += 1
    remaining = MAX_FAILED_ATTEMPTS - record["failed_attempts"]
    if remaining <= 0:
        record["locked_until"] = time.time() + LOCK_DURATION
        record["failed_attempts"] = 0
        return f"Too many failed attempts. Account locked for {LOCK_DURATION} seconds."
    return f"Invalid credentials. {remaining} attempts remaining."

def handle_client(conn: socket.socket, addr) -> None:
    logging.info("Connection from %s", addr)
    with conn:
        try:
            raw = conn.recv(4096)
            if not raw:
                return
            payload = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            send_response(conn, "error", "Payload must be JSON with username, password, and otp.")
            return

        username = payload.get("username", "").strip()
        password = payload.get("password", "")
        otp = payload.get("otp", "")

        record = USER_DB.get(username)
        if not record:
            send_response(conn, "error", "Unknown username.")
            return

        now = time.time()
        if record["locked_until"] > now:
            remaining = int(record["locked_until"] - now)
            send_response(conn, "locked", f"Account locked. Try again in {remaining} seconds.")
            return

        if not verify_password(record, password):
            message = handle_failed_attempt(record)
            send_response(conn, "error", message)
            return

        if not verify_totp(record, otp):
            message = handle_failed_attempt(record)
            send_response(conn, "error", "OTP verification failed. " + message)
            return

        record["failed_attempts"] = 0
        send_response(conn, "ok", "Authentication success. Access granted.")


def start_server() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    initialize_users()
    logging.info("Listening on %s:%s", HOST, PORT)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen()
        while True:
            conn, addr = sock.accept()
            # Keep the listener responsive by handling each client in its own thread.
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()

