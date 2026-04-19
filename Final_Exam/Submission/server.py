#!/usr/bin/env python3

import hashlib
import hmac
import json
import logging
import os
import socket
import threading

import cryptography.fernet
import pyotp  # type: ignore

# I added type: ignore to some imports because I use mypy for static type checking and throws errors

HOST = os.getenv("FINAL_EXAM_SERVER_HOST", "0.0.0.0")
PORT = int(os.getenv("FINAL_EXAM_SERVER_PORT", "9000"))
PASSWORD = os.getenv("FINAL_EXAM_PASSWORD")
TOTP_SECRET = os.getenv("FINAL_EXAM_TOTP_SECRET")
FERNET_KEY = os.getenv("FINAL_EXAM_FERNET_KEY")

if not PASSWORD:
    raise RuntimeError("Missing FINAL_EXAM_PASSWORD")
if not TOTP_SECRET:
    raise RuntimeError("Missing FINAL_EXAM_TOTP_SECRET")
if not FERNET_KEY:
    raise RuntimeError("Missing FINAL_EXAM_FERNET_KEY")

SALT = "final_exam_salt_2026"
PASSWORD_HASH = hashlib.sha256(f"{SALT}{PASSWORD}".encode("utf-8")).hexdigest()
fernet = cryptography.fernet.Fernet(FERNET_KEY.encode("utf-8"))


def verify_password(password: str) -> bool:
    # constant-time compare to prevent timing attacks
    payload = f"{SALT}{password}".encode("utf-8")
    return hmac.compare_digest(PASSWORD_HASH, hashlib.sha256(payload).hexdigest())


def verify_totp(token: str) -> bool:
    return pyotp.TOTP(TOTP_SECRET).verify(token)  # validates current 30s window


def send_json(conn: socket.socket, status: str, message: str) -> None:
    data = json.dumps({"status": status, "message": message}).encode("utf-8")
    conn.sendall(data)


def handle_client(conn: socket.socket, addr) -> None:
    """
    - Receive and parse client credentials (password + TOTP).
    - Reject connection if either factor fails.
    - Read length-prefixed encrypted payload.
    - Decrypt and save to server_architect_manifesto.txt.
    """
    logging.info("Connection from %s", addr)
    try:
        raw = conn.recv(4096)
        if not raw:
            logging.warning("Client disconnected before sending credentials: %s", addr)
            return

        try:
            creds = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            send_json(conn, "error", "Payload must be valid JSON")
            return

        password = creds.get("password", "")
        otp = creds.get("otp", "")

        # verify both factors before accepting any payload
        if not verify_password(password):
            send_json(conn, "error", "Invalid password")
            logging.warning("Invalid password from %s", addr)
            return
        if not verify_totp(otp):
            send_json(conn, "error", "Invalid OTP")
            logging.warning("Invalid OTP from %s", addr)
            return

        send_json(conn, "ok", "Authentication success. Ready to receive payload.")
        logging.info("MFA passed for %s", addr)

        # read 4-byte big-endian length header
        length_buf = b""
        while len(length_buf) < 4:
            chunk = conn.recv(4 - len(length_buf))
            if not chunk:
                logging.warning("Client disconnected during length header: %s", addr)
                return
            length_buf += chunk

        total = int.from_bytes(length_buf, "big")

        # loop until all encrypted bytes are received
        data = b""
        while len(data) < total:
            chunk = conn.recv(min(4096, total - len(data)))
            if not chunk:
                logging.warning("Client disconnected during payload: %s", addr)
                return
            data += chunk

        # decrypt - Fernet raises if ciphertext is tampered or truncated
        try:
            plaintext = fernet.decrypt(data)
            message = plaintext.decode("utf-8")
        except Exception as e:
            logging.error("Decryption failed for %s: %s", addr, e)
            send_json(conn, "error", "Decryption failed")
            return

        out_path = "server_architect_manifesto.txt"
        with open(out_path, "w") as f:
            f.write(message)

        logging.info("Payload saved to %s", out_path)
        send_json(conn, "ok", f"Payload received and decrypted. Saved to {out_path}")

    except Exception as e:
        logging.error("Unhandled exception for %s: %s", addr, e)
    finally:
        conn.close()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    logging.info("Starting server on %s:%s", HOST, PORT)
    logging.info("MFA: password + TOTP required before file transfer")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen()
        sock.settimeout(1.0)  # allow Ctrl+C to interrupt accept on Windows
        logging.info("Server listening on %s:%s", HOST, PORT)

        while True:
            try:
                conn, addr = sock.accept()
                # handle each client in its own thread to keep listener responsive
                threading.Thread(
                    target=handle_client, args=(conn, addr), daemon=True
                ).start()
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                logging.info("Server shutting down.")
                break


if __name__ == "__main__":
    main()
