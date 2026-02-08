from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS
from logger import log_packet
from datetime import datetime
import signal, sys

# ---- counters ----
stats = {
    "TOTAL": 0,
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "ARP": 0,
    "DNS": 0
}

# ---- app protocol ports ----
APP_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP"
}

def process_packet(packet):
    stats["TOTAL"] += 1
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    # ---- ARP ----
    if packet.haslayer(ARP):
        stats["ARP"] += 1
        output = f"[{timestamp} UTC] ARP packet detected"
        print(output)
        log_packet(output)
        return

    # ---- IP ----
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = "IP"
    src_port = "-"
    dst_port = "-"
    app_proto = "-"

    # ---- ICMP ----
    if packet.haslayer(ICMP):
        stats["ICMP"] += 1
        protocol = "ICMP"

    # ---- TCP ----
    elif packet.haslayer(TCP):
        stats["TCP"] += 1
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    # ---- UDP ----
    elif packet.haslayer(UDP):
        stats["UDP"] += 1
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # ---- DNS ----
    if packet.haslayer(DNS):
        stats["DNS"] += 1
        app_proto = "DNS"

    # ---- Port-based application detection ----
    for port in (src_port, dst_port):
        if isinstance(port, int) and port in APP_PORTS:
            app_proto = APP_PORTS[port]
            break

    output = (
        f"[{timestamp} UTC] "
        f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
        f"{protocol} | {app_proto}"
    )

    print(output)
    log_packet(output)

# ---- graceful shutdown ----
def shutdown(sig, frame):
    print("\n--- Capture Summary ---")
    for k, v in stats.items():
        print(f"{k}: {v}")
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown)

# ---- start ----
if __name__ == "__main__":
    iface = "eth0"  # change if needed

    print(f"Listening on {iface} (IP + ARP traffic)")
    print("CTRL+C to stop\n")

    sniff(
        iface=iface,
        filter="ip or arp",
        prn=process_packet,
        store=False
    )
