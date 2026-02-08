from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS
from logger import log_packet
from datetime import datetime, timezone
import signal
import sys
import time
from collections import defaultdict

# ---------------- CONFIG ----------------
INTERFACE = "eth0"          # change if needed
TIME_WINDOW = 10            # seconds

PORT_SCAN_THRESHOLD = 20
SSH_BRUTE_THRESHOLD = 10
ICMP_THRESHOLD = 30
DNS_THRESHOLD = 50

INSECURE_PORTS = {
    21: "FTP",
    23: "TELNET",
    25: "SMTP",
    445: "SMB",
    3389: "RDP"
}

# ---------------- TRACKERS ----------------
port_scan_tracker = defaultdict(set)
ssh_tracker = defaultdict(list)
icmp_tracker = defaultdict(list)
dns_tracker = defaultdict(list)

# ---------------- ALERT FUNCTION ----------------
def alert(level, message):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    alert_msg = f"[ALERT][{level}][{timestamp} UTC] {message}"
    print(alert_msg)
    log_packet(alert_msg)

# ---------------- PACKET HANDLER ----------------
def process_packet(packet):
    now = time.time()
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # Ignore non-IP except ARP
    if packet.haslayer(ARP):
        return

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # -------- ICMP FLOOD --------
    if packet.haslayer(ICMP):
        icmp_tracker[src_ip].append(now)
        icmp_tracker[src_ip] = [t for t in icmp_tracker[src_ip] if now - t <= TIME_WINDOW]

        if len(icmp_tracker[src_ip]) > ICMP_THRESHOLD:
            alert("MEDIUM", f"Possible ICMP flood from {src_ip}")
        return

    # -------- TCP / UDP --------
    proto = None
    sport = "-"
    dport = "-"

    if packet.haslayer(TCP):
        proto = "TCP"
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = packet[TCP].flags

        # ---- Port scan detection (SYN only) ----
        if flags == "S":
            port_scan_tracker[src_ip].add(dport)
            if len(port_scan_tracker[src_ip]) > PORT_SCAN_THRESHOLD:
                alert("HIGH", f"Port scan detected from {src_ip}")

        # ---- SSH brute force ----
        if dport == 22:
            ssh_tracker[src_ip].append(now)
            ssh_tracker[src_ip] = [t for t in ssh_tracker[src_ip] if now - t <= TIME_WINDOW]
            if len(ssh_tracker[src_ip]) > SSH_BRUTE_THRESHOLD:
                alert("HIGH", f"Possible SSH brute force from {src_ip}")

    elif packet.haslayer(UDP):
        proto = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport

    else:
        return

    # -------- Insecure protocols --------
    if isinstance(dport, int) and dport in INSECURE_PORTS:
        alert("LOW", f"{INSECURE_PORTS[dport]} traffic from {src_ip} to {dst_ip}")

    # -------- DNS abuse --------
    if packet.haslayer(DNS):
        dns_tracker[src_ip].append(now)
        dns_tracker[src_ip] = [t for t in dns_tracker[src_ip] if now - t <= TIME_WINDOW]
        if len(dns_tracker[src_ip]) > DNS_THRESHOLD:
            alert("MEDIUM", f"Unusual DNS activity from {src_ip}")

    # -------- Normal logging --------
    log_packet(
        f"[{timestamp} UTC] {src_ip}:{sport} -> {dst_ip}:{dport} | {proto}"
    )

# ---------------- GRACEFUL SHUTDOWN ----------------
def shutdown(sig, frame):
    print("\n--- Phase 2 monitor stopped ---")
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown)

# ---------------- START ----------------
if __name__ == "__main__":
    print("Phase 2 IDS started")
    print("Monitoring scans, brute force, ICMP, DNS abuse\n")

    sniff(
        iface=INTERFACE,
        filter="ip or arp",
        prn=process_packet,
        store=False
    )
