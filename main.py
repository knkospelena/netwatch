from scapy.all import sniff, IP, TCP
from datetime import datetime
import os

# =============================
# Config
# =============================
INTERFACE = "eth0"
LOG_FILE = "alerts.log"
ALERT_THRESHOLD = 7       # Risk score threshold

RISK_SCORES = {
    "TELNET": 5,
    "FTP": 4,
    "HTTP": 2,
    "SSH_WEAK": 3,
    "PORT_SCAN": 4
}

# =============================
# Tracking
# =============================
host_events = {}   # keep track of unique event types per host
host_risk = {}     # cumulative risk per host

# =============================
# Utility functions
# =============================
def log_alert(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {message}"
    print(entry)
    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")

def correlate(src_ip, event):
    """Add event only if it hasn't been triggered yet for this host."""
    if src_ip not in host_events:
        host_events[src_ip] = set()
        host_risk[src_ip] = 0

    if event not in host_events[src_ip]:
        host_events[src_ip].add(event)
        host_risk[src_ip] += RISK_SCORES.get(event, 0)

        # Only alert when a **new unique event** is added
        risk = host_risk[src_ip]
        status = "HIGH" if risk >= ALERT_THRESHOLD else "MEDIUM"
        log_alert(f"[ALERT] {src_ip} | Risk: {status} ({risk}) | Event: {event}")

# =============================
# Packet analysis
# =============================
def analyze_packet(packet):
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    src_ip = packet[IP].src
    dst_port = packet[TCP].dport

    # Detect specific protocols
    if dst_port == 23:
        correlate(src_ip, "TELNET")
    elif dst_port == 21:
        correlate(src_ip, "FTP")
    elif dst_port == 80:
        correlate(src_ip, "HTTP")

    # Simple port scan detection (SYN packet)
    if packet[TCP].flags == "S":
        correlate(src_ip, "PORT_SCAN")

# =============================
# Summary report
# =============================
def print_summary():
    print("\n========== SECURITY SUMMARY ==========")
    for ip, events in host_events.items():
        risk = host_risk[ip]
        status = "HIGH" if risk >= ALERT_THRESHOLD else "MEDIUM"
        print(f"Host: {ip}")
        print(f"  Risk: {status} ({risk})")
        print(f"  Events: {', '.join(events)}")
        print("----------------------------------")
    print("=====================================\n")

# =============================
# Main
# =============================
if __name__ == "__main__":
    print("Phase 3 IDS – Running on interface", INTERFACE)
    print("Press Ctrl+C to stop and see summary\n")

    try:
        sniff(iface=INTERFACE, prn=analyze_packet, store=False)
    except KeyboardInterrupt:
        print_summary()
        print("[+] IDS stopped safely")
