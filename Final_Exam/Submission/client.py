#!/usr/bin/env python3

import json
import os
import socket
import sys
from typing import Tuple

import cryptography.fernet
import nmap  # type: ignore
import pyotp
import stepic  # type: ignore
from PIL import Image  # type: ignore

# I added type: ignore to some imports because I use mypy for static type checking and throws errors

def scan_port(host: str, port: int) -> Tuple[bool, str]:
    """
    - Run a TCP connect scan with version detection against host:port.
    - Save all results to client_scan_results.log.
    - Return (is_open, service_name).
    """
    scanner = nmap.PortScanner()
    try:
        scanner.scan(host, str(port), "-sT -sV --host-timeout 20s")
    except Exception as e:
        print(f"[ERROR] nmap scan failed: {e}")
        with open("client_scan_results.log", "w") as lf:
            lf.write(f"Scan failed for {host}:{port}\nError: {e}\n")
        return False, ""

    # build log lines from scan results
    log_lines = [f"Nmap scan results for {host}:{port}\n", "-" * 40 + "\n"]
    result_open, result_name = False, ""

    for h in scanner.all_hosts():
        for proto in scanner[h].all_protocols():
            for p in scanner[h][proto].keys():
                info = scanner[h][proto][p]
                state = info["state"]
                name = info.get("name", "unknown")
                version = info.get("version", "")
                log_lines.append(
                    f"Host: {h}  Port: {p}/{proto}  State: {state}"
                    f"  Service: {name}  Version: {version}\n"
                )
                if p == port:
                    result_open = state == "open"
                    result_name = name

    with open("client_scan_results.log", "w") as lf:
        lf.writelines(log_lines)

    print("[INFO] Scan results saved to client_scan_results.log")
    return result_open, result_name


def extract_hidden(image_path: str) -> str:
    """
    - Open image_path using Pillow.
    - Decode the LSB-embedded message using stepic.
    - Validate the recovered message contains the expected marker.
    - Return the message as a string.
    """
    try:
        with Image.open(image_path) as im:
            data = stepic.decode(im)
    except FileNotFoundError:
        raise FileNotFoundError(f"{image_path} not found")
    except Exception as e:
        raise ValueError(f"Could not decode hidden data: {e}")

    if data is None:
        raise ValueError("No hidden data found in image")

    # stepic may return bytes or str depending on version
    message = data if isinstance(data, str) else data.decode("utf-8")
    if "The vault is" not in message:
        raise ValueError("Hidden message does not contain the expected prefix")

    return message


def main() -> None:
    host = os.getenv("FINAL_EXAM_SERVER_HOST", "127.0.0.1")
    port = int(os.getenv("FINAL_EXAM_SERVER_PORT", "9000"))
    password = os.getenv("FINAL_EXAM_PASSWORD")
    otp_secret = os.getenv("FINAL_EXAM_TOTP_SECRET")
    fernet_key = os.getenv("FINAL_EXAM_FERNET_KEY")

    if not password:
        raise RuntimeError("Missing FINAL_EXAM_PASSWORD")
    if not otp_secret:
        raise RuntimeError("Missing FINAL_EXAM_TOTP_SECRET")
    if not fernet_key:
        raise RuntimeError("Missing FINAL_EXAM_FERNET_KEY")

    # pre-flight: confirm server is reachable before sending anything sensitive
    print(f"[INFO] Scanning {host}:{port}...")
    is_open, service = scan_port(host, port)
    if not is_open:
        print(f"[ERROR] Port {port} is not open on {host}. Exiting.")
        sys.exit(1)

    print(f"[INFO] Port {port} is open (service: {service}).")

    # steganography: extract hidden manifesto from evidence.png
    print("[INFO] Extracting hidden manifesto...")
    try:
        manifesto = extract_hidden("evidence.png")
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    print("[INFO] Hidden manifesto extracted.")
    with open("client_architect_manifesto.txt", "w") as mf:
        mf.write(manifesto)

    print("[INFO] Manifesto saved to client_architect_manifesto.txt")

    # encrypt before opening the socket - plaintext never touches the network
    f = cryptography.fernet.Fernet(fernet_key.encode("utf-8"))
    encrypted = f.encrypt(manifesto.encode("utf-8"))
    print(f"[INFO] Encrypted manifesto: {len(encrypted)} bytes")

    # generate TOTP as late as possible to avoid window expiry
    current_otp = pyotp.TOTP(otp_secret).now()

    try:
        sock = socket.create_connection((host, port), timeout=10)
    except Exception as e:
        print(f"[ERROR] Could not connect to {host}:{port}: {e}")
        sys.exit(1)

    print(f"[INFO] Connected to {host}:{port}")

    with sock:
        sock.settimeout(15)

        # send credentials and wait for MFA result before sending payload
        creds = json.dumps({"password": password, "otp": current_otp}).encode("utf-8")
        sock.sendall(creds)
        resp_raw = sock.recv(4096)
        try:
            resp = json.loads(resp_raw.decode("utf-8"))
        except Exception:
            print("[ERROR] Invalid response from server")
            sys.exit(1)

        print(f"[{resp['status']}] {resp['message']}")
        if resp.get("status") != "ok":
            print("[ERROR] Authentication failed. Aborting.")
            sys.exit(1)

        # length-prefix framing: TCP is a stream, server needs to know payload size
        sock.sendall(len(encrypted).to_bytes(4, "big"))
        sock.sendall(encrypted)
        print(f"[INFO] Sent {len(encrypted)} encrypted bytes")

        final = sock.recv(4096)
        try:
            result = json.loads(final.decode("utf-8"))
        except Exception:
            print("[WARN] Unexpected server response after sending payload")
            return

        print(f"[{result['status']}] {result['message']}")


if __name__ == "__main__":
    main()
