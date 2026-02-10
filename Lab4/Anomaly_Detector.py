from scapy.all import rdpcap, IP, TCP, UDP

# 'deque' is a double-ended queue optimized for fast append/remove operations (https://docs.python.org/3/library/collections.html#collections.deque)
from collections import defaultdict, deque

WINDOW_SECONDS = 5

THRESHOLD = 20

PCAP_FILE = "botnet-capture-20110812-rbot.pcap"

def main():
    print("=" * 50, flush=True)
    print("Starting PCAP analysis...", flush=True)
    print(f"Loading PCAP file: {PCAP_FILE} (~60 seconds)...", flush=True)
    try:
        packets = rdpcap(PCAP_FILE)
        print(f"Loaded {len(packets)} packets. Analyzing...", flush=True)
        print("=" * 50, flush=True)
    except FileNotFoundError:
        print(f"PCAP not found: {PCAP_FILE}", flush=True)
        return
    except Exception as e:
        print(f"Failed to read PCAP: {e}", flush=True)
        return

    tcp_total = 0
    udp_total = 0

    # defaultdict(deque) automatically creates a deque for each new IP
    times_by_ip = defaultdict(deque)
    
    # set to store IP addresses that have already triggered an alert, this prevents duplicate alerts from the same IP
    alerted = set()

    for idx, pkt in enumerate(packets):
        
        if IP not in pkt:
            continue

        is_tcp = TCP in pkt
        is_udp = UDP in pkt
        if not (is_tcp or is_udp):
            continue

        if is_tcp:
            tcp_total += 1
        else:
            udp_total += 1

        src_ip = pkt[IP].src
        t = float(getattr(pkt, "time", 0.0))

        q = times_by_ip[src_ip]
        q.append(t)

        # remove timestamps older than WINDOW_SECONDS
        # calculate the cutoff time (5 seconds before current time)
        cutoff = t - WINDOW_SECONDS
        # popleft() will remove from the front of the deque (oldest timestamps)
        while q and q[0] < cutoff:
            q.popleft()

        if len(q) > THRESHOLD and src_ip not in alerted:
            alerted.add(src_ip)
            print(f"[ALERT] Possible flooding: {src_ip} sent {len(q)} packets in {WINDOW_SECONDS} seconds", flush=True)

    print("\n" + "=" * 50, flush=True)
    print("Analysis complete!", flush=True)
    print("=" * 50, flush=True)
    print("PCAP Summary", flush=True)
    print("=" * 50, flush=True)
    print(f"Total TCP Packets:     {tcp_total:>10,}", flush=True)
    print(f"Total UDP Packets:     {udp_total:>10,}", flush=True)
    print(f"Suspicious IPs Found:  {len(alerted):>10}", flush=True)
    print("=" * 50, flush=True)

if __name__ == "__main__":
    main()

