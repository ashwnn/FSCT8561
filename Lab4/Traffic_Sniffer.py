from scapy.all import sniff, Ether, IP, TCP, UDP, Raw
import datetime
import re
import os

# Configuration
PACKETS_PER_CAPTURE = 50
INTERFACE = None  # None = use default interface

# Output files
REPORT_FILE = "capture_report.txt"

# Capture filters: (BPF_filter, label)
CAPTURES = [
    ("tcp", "TCP"),
    ("tcp port 80", "HTTP"),
    ("udp port 53", "DNS"),
]

# Patterns for detecting sensitive data
SENSITIVE_PATTERNS = [
    re.compile(r"(user(name)?|login)\s*=\s*[^&\s]+", re.I),
    re.compile(r"(pass(word)?|pwd)\s*=\s*[^&\s]+", re.I),
    re.compile(r"authorization:\s*basic\s+[a-z0-9+/=]+", re.I),
]

# HTTP headers that may leak metadata
HTTP_METADATA_HEADERS = {
    "user-agent", "server", "cookie", "set-cookie", "referer", "authorization"
}

def format_time(timestamp):
    try:
        return datetime.datetime.fromtimestamp(float(timestamp)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "unknown-time"

def get_payload(packet):
    if Raw not in packet:
        return ""
    try:
        return bytes(packet[Raw].load).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def is_http(packet):
    if TCP not in packet:
        return False
    if packet[TCP].sport != 80 and packet[TCP].dport != 80:
        return False
    
    payload = get_payload(packet)
    if not payload:
        return False
    
    first_line = payload.splitlines()[0].strip() if payload.splitlines() else ""
    http_methods = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ")
    return first_line.startswith(http_methods) or "HTTP/" in first_line

def find_sensitive_data(text):
    matches = []
    for pattern in SENSITIVE_PATTERNS:
        match = pattern.search(text)
        if match:
            matches.append(match.group(0))
    return matches

def process_packet(packet, stats):
    timestamp = format_time(getattr(packet, "time", 0))
    
    # Extract MAC addresses
    mac_src = mac_dst = "-"
    if Ether in packet:
        mac_src = packet[Ether].src
        mac_dst = packet[Ether].dst
    
    # Extract IP addresses
    ip_src = ip_dst = "-"
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
    
    # Determine protocol and ports
    protocol = "OTHER"
    src_port = dst_port = "-"
    flags = "-"
    
    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = str(packet[TCP].flags)
    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    
    # Classify protocol more specifically
    if is_http(packet):
        protocol = "HTTP"
    elif UDP in packet and (packet[UDP].sport == 53 or packet[UDP].dport == 53):
        protocol = "DNS"
    
    # Format and log packet info
    packet_len = len(packet)
    log_line = (
        f"[{timestamp}] {protocol:5} "
        f"MAC {mac_src} -> {mac_dst} | "
        f"IP {ip_src}:{src_port} -> {ip_dst}:{dst_port} | "
        f"len={packet_len} flags={flags}"
    )
    
    print(log_line)
    
    stats[protocol] = stats.get(protocol, 0) + 1
    
    # Analyze payload for security concerns
    payload = get_payload(packet)
    if not payload:
        return
    
    # Check for sensitive data
    sensitive_matches = find_sensitive_data(payload)
    if sensitive_matches:
        msg = f"  [!] SENSITIVE: {protocol} packet from {ip_src}:{src_port}"
        print(msg)
        for match in sensitive_matches[:3]:
            detail = f"      - {match}"
            print(detail)
    
    # Check for HTTP metadata leakage
    if protocol == "HTTP":
        for line in payload.splitlines()[:20]:
            header = line.split(":", 1)[0].strip().lower()
            if header in HTTP_METADATA_HEADERS:
                msg = f"  [i] HTTP HEADER: {line.strip()}"
                print(msg)


def capture_traffic(bpf_filter, label, stats):
    print(f"\n=== Capturing {label} ({bpf_filter}) ===")
    
    sniff(
        iface=INTERFACE,
        filter=bpf_filter,
        count=PACKETS_PER_CAPTURE,
        store=False,
        prn=lambda pkt: process_packet(pkt, stats),
    )

def write_report(stats):
    total = sum(stats.values())
    
    report_lines = [
        "=" * 70,
        "PACKET CAPTURE REPORT",
        "=" * 70,
        f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "SUMMARY",
        "-" * 70,
    ]
    
    for protocol in sorted(stats.keys()):
        count = stats[protocol]
        percentage = (count / total * 100) if total > 0 else 0
        report_lines.append(f"  {protocol:6} : {count:4} packets ({percentage:5.1f}%)")
    
    report_lines.extend([
        "-" * 70,
        f"  {'TOTAL':6} : {total:4} packets",
        "",
        "FILES GENERATED",
        "-" * 70,
        f"  - {REPORT_FILE}: This report",
        "=" * 70,
    ])
    
    report_text = "\n".join(report_lines)
    print("\n" + report_text)
    
    with open(REPORT_FILE, "w") as f:
        f.write(report_text)
    
    print(f"\n[+] Report saved to: {REPORT_FILE}")
    print(f"[+] Log saved to: {LOG_FILE}")


def main():
    # Clean up old files
    if os.path.exists(REPORT_FILE):
        os.remove(REPORT_FILE)
    
    stats = {}
    
    try:
        # Capture traffic for each filter
        for bpf_filter, label in CAPTURES:
            capture_traffic(bpf_filter, label, stats)
        
        # Generate report
        write_report(stats)
        
    except PermissionError:
        print("[!] ERROR: Run with sudo to capture packets")
        return
    except Exception as e:
        print(f"[!] ERROR: {e}")
        return

if __name__ == "__main__":
    main()
