import hashlib
import json
import sys
import time
from collections import defaultdict, deque

import pyotp
from scapy.all import IP, TCP, UDP, Raw, sniff

WINDOW_SECONDS = 5
THRESHOLD = 20
MAX_CLOCK_SKEW_SECONDS = 30
DEFAULT_CAPTURE_COUNT = 50
MAX_AUTH_FAILS = 5
LOCKOUT_SECONDS = 30

USER_DB = {
    "admin": {
        "salt": "srds_admin_salt",
        "password_hash": hashlib.sha256(
            "srds_admin_salt".encode("utf-8") + "SuperSecretLinux33!".encode("utf-8")
        ).hexdigest(),
        "otp_secret": "JBSWY3DPEHPK3PXP",
    }
}

SENSITIVE_KEYWORDS = ["password", "token", "authorization", "set-cookie", "api_key"]
auth_fail_count = defaultdict(int)
lockout_until = {}
times_by_ip = defaultdict(deque)
seen_message_ids = set()
last_sequence_by_session = {}
alerted_ips = set()
tcp_total = 0
udp_total = 0

# Salted hash makes leaked DB values less reusable.
def hash_password(salt: str, password: str) -> str:
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()

# Generic failures prevent factor enumeration.
def verify_mfa(username: str, password: str, otp_code: str) -> bool:
    now = int(time.time())
    if now < lockout_until.get(username, 0):
        print("Authentication failed.")
        return False

    user = USER_DB.get(username)
    if not user:
        print("Authentication failed.")
        return False

    pwd_ok = hash_password(user["salt"], password) == user["password_hash"]
    otp_ok = pyotp.TOTP(user["otp_secret"]).verify(str(otp_code), valid_window=1)
    if not (pwd_ok and otp_ok):
        auth_fail_count[username] += 1
        if auth_fail_count[username] >= MAX_AUTH_FAILS:
            lockout_until[username] = now + LOCKOUT_SECONDS
        print("Authentication failed.")
        return False

    auth_fail_count[username] = 0
    lockout_until.pop(username, None)
    print("Authentication success.")
    return True

# Ignore malformed bytes so crafted payloads do not crash detection.
def safe_decode(raw_bytes: bytes) -> str:
    return raw_bytes.decode("utf-8", errors="ignore") if raw_bytes else ""

# Only provide a snippet to reduce possibly sensitive data being stored
def check_sensitive_payload(payload: str, src_ip: str) -> None:
    low = payload.lower()
    for kw in SENSITIVE_KEYWORDS:
        if kw in low:
            snippet = payload.replace("\\r", " ").replace("\\n", " ").strip()[:120]
            print(f"[WARN] Sensitive keyword '{kw}' from {src_ip} | snippet='{snippet}'")
            return

def validate_srds_message(payload: str, src_ip: str) -> None:
    # Check replay + freshness + integrity on JSON control messages.
    if not (payload.startswith("{") and payload.endswith("}")):
        return
    try:
        msg = json.loads(payload)
    except Exception:
        return

    required = {"session_id", "message_id", "timestamp", "sequence", "command", "integrity_hash"}
    if not required.issubset(msg.keys()):
        print(f"[ALERT] ERR_MALFORMED_INPUT from {src_ip}")
        return

    sid, mid = str(msg["session_id"]), str(msg["message_id"])
    if mid in seen_message_ids:
        print(f"[ALERT] ERR_REPLAY from {src_ip}: duplicate message_id={mid}")
        return
    seen_message_ids.add(mid)

    try:
        ts, seq = int(msg["timestamp"]), int(msg["sequence"])
    except (TypeError, ValueError):
        print(f"[ALERT] ERR_MALFORMED_INPUT from {src_ip}: message_id={mid}")
        return

    skew = abs(int(time.time()) - ts)
    if skew > MAX_CLOCK_SKEW_SECONDS:
        print(f"[ALERT] ERR_EXPIRED from {src_ip}: message_id={mid}, skew={skew}s")
        return

    last_seq = last_sequence_by_session.get(sid)
    if last_seq is not None and seq <= last_seq:
        print(f"[ALERT] ERR_REPLAY from {src_ip}: session={sid}, seq={seq}, last={last_seq}")
        return
    last_sequence_by_session[sid] = seq

    expected = hashlib.sha256(f"{sid}|{mid}|{ts}|{seq}|{msg['command']}".encode("utf-8")).hexdigest()
    if str(msg["integrity_hash"]) != expected:
        print(f"[ALERT] ERR_INVALID_SIG from {src_ip}: message_id={mid}")

def packet_callback(pkt) -> None:
    global tcp_total, udp_total
    if IP not in pkt or (TCP not in pkt and UDP not in pkt):
        return

    src_ip = pkt[IP].src
    now = float(getattr(pkt, "time", time.time()))
    tcp_total += int(TCP in pkt)
    udp_total += int(UDP in pkt)

    q = times_by_ip[src_ip]
    q.append(now)
    cutoff = now - WINDOW_SECONDS
    while q and q[0] < cutoff:
        q.popleft()

    # One alert per source keeps logs readable during flood attempts.
    if len(q) > THRESHOLD and src_ip not in alerted_ips:
        alerted_ips.add(src_ip)
        print(f"[ALERT] Possible flood/scan from {src_ip}: {len(q)} packets in {WINDOW_SECONDS}s")

    if Raw in pkt:
        payload = safe_decode(bytes(pkt[Raw].load)).strip()
        if payload:
            check_sensitive_payload(payload, src_ip)
            validate_srds_message(payload, src_ip)

# Filter DNS, HTTP and Store=False reduces chance of persisting sensitive traffic.
def analyze(packet_count: int, iface: str | None = None) -> None:
    sniff(
        filter="tcp port 80 or tcp port 53 or udp port 53",
        count=packet_count,
        iface=iface,
        prn=packet_callback,
        store=False,
    )

def print_summary() -> None:
    print("\\n=== SRDS Attack Detection Summary ===")
    print(f"TCP: {tcp_total} | UDP: {udp_total} | Suspicious IPs: {len(alerted_ips)}")
    print(f"Tracked Message IDs: {len(seen_message_ids)}")
    for ip in sorted(alerted_ips):
        print(f" - {ip}")

def main() -> None:
    if len(sys.argv) < 4:
        print("Usage: python srds.py <username> <password> <otp> [count] [iface]")
        return

    username, password, otp_code = sys.argv[1], sys.argv[2], sys.argv[3]
    if not verify_mfa(username, password, otp_code):
        return

    count = DEFAULT_CAPTURE_COUNT
    iface = None
    if len(sys.argv) >= 5:
        try:
            count = int(sys.argv[4])
        except ValueError:
            print("Invalid packet count. Using default 50.")
    if len(sys.argv) >= 6:
        iface = sys.argv[5]

    analyze(count, iface)
    print_summary()

if __name__ == "__main__":
    main()