#!/usr/bin/env python3

from scapy.all import sniff, Ether, IP, TCP, UDP, Raw  # type: ignore

COUNT = 50

SENSITIVE_KEYWORDS = [
    "username",
    "user=",
    "password",
    "pass=",
    "passwd",
    "pwd=",
    "login",
    "authorization:",
    "token",
    "apikey",
    "api_key",
]

HTTP_METADATA_MARKERS = [
    "cookie:",
    "set-cookie:",
    "user-agent:",
    "server:",
]

current_label = "CAPTURE"
tcp_count = 0
udp_count = 0

# decode to utf-8 catching errors
def safe_decode(b: bytes) -> str:
    try:
        return b.decode("utf-8", errors="ignore")
    except Exception:
        return ""

def packet_callback(pkt) -> None:
    global tcp_count, udp_count

    ts = float(getattr(pkt, "time", 0.0))
    length = len(pkt)

    src_mac = dst_mac = "N/A"
    if Ether in pkt:
        src_mac = pkt[Ether].src
        dst_mac = pkt[Ether].dst

    src_ip = dst_ip = "N/A"
    sport = dport = "N/A"
    proto = "OTHER"
    flags = ""

    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

    if TCP in pkt:
        proto = "TCP"
        sport = str(pkt[TCP].sport)
        dport = str(pkt[TCP].dport)
        flags = str(pkt[TCP].flags)
        tcp_count += 1
    elif UDP in pkt:
        proto = "UDP"
        sport = str(pkt[UDP].sport)
        dport = str(pkt[UDP].dport)
        udp_count += 1

    line = f"[{current_label}] time={ts:.6f} {src_ip}:{sport} -> {dst_ip}:{dport} {proto} len={length} mac={src_mac}->{dst_mac}"
    if flags:
        line += f" flags={flags}"
    print(line)

    if Raw in pkt:
        payload = safe_decode(bytes(pkt[Raw].load))
        low = payload.lower()

        for kw in SENSITIVE_KEYWORDS:
            if kw in low:
                snippet = payload.replace("\r", " ").replace("\n", " ").strip()[:120]
                print(f"  [{current_label}] POSSIBLE SENSITIVE DATA: matched '{kw}' | payload='{snippet}'")
                break

        for marker in HTTP_METADATA_MARKERS:
            if marker in low:
                print(f"  [{current_label}] HTTP METADATA EXPOSURE: found '{marker.strip()}' header")
                break

def main() -> None:
    global current_label

    current_label = "TCP_ONLY"
    sniff(filter="tcp", count=COUNT, prn=packet_callback)

    current_label = "HTTP_80"
    sniff(filter="tcp port 80", count=COUNT, prn=packet_callback)

    current_label = "DNS_53"
    sniff(filter="udp port 53", count=COUNT, prn=packet_callback)

    print(f"Total TCP Packets: {tcp_count}")
    print(f"Total UDP Packets: {udp_count}")

if __name__ == "__main__":
    main()

