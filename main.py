from scapy.all import sniff, IP, TCP
from datetime import datetime
import os

# =============================
# Configuration
# =============================
INTERFACE = "eth0"     # change if needed
LOG_FILE = "alerts.log"
AUTO_BLOCK = False     # set True to enable iptables blocking
ALERT_THRESHOLD = 7    # risk score threshold

# =============================
# Risk scoring
# =============================
RISK_SCORES = {
    "TELNET": 5,
    "FTP": 4,
    "HTTP": 2,
    "SSH_WEAK": 3,
    "PORT_SCAN": 4
}

# =============================
# Tracking structures
# =============================
host_events = {}
host_risk = {}

# =============================
# Utility functions
# =============================
def log_alert(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {message}"
    print(entry)

    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")

def block_ip(ip):
    if AUTO_BLOCK:
        os.system(f"iptables -A INPUT -s {ip} -j DROP")
        log_alert(f"[RESPONSE] IP blocked: {ip}")

def correlate(src_ip, event):
    if src_ip not in host_events:
        host_events[src_ip] = []
        host_risk[src_ip] = 0

    host_events[src_ip].append(event)
    host_risk[src_ip] += RISK_SCORES.get(event, 0)

    if host_risk[src_ip] >= ALERT_THRESHOLD:
        log_alert(
            f"[CRITICAL] {src_ip} | Risk Score: {host_risk[src_ip]} | Events: {host_events[src_ip]}"
        )
        block_ip(src_ip)

# =============================
# Packet analysis
# =============================
def analyze_packet(packet):
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    src_ip = packet[IP].src
    dst_port = packet[TCP].dport

    # Telnet detection
    if dst_port == 23:
        log_alert(f"[ALERT] Telnet detected from {src_ip}")
        correlate(src_ip, "TELNET")

    # FTP detection
    elif dst_port == 21:
        log_alert(f"[ALERT] FTP detected from {src_ip}")
        correlate(src_ip, "FTP")

    # HTTP detection
    elif dst_port == 80:
        log_alert(f"[INFO] HTTP traffic from {src_ip}")
        correlate(src_ip, "HTTP")

    # Possible port scan (many SYN packets)
    if packet[TCP].flags == "S":
        syn_count = host_events.get(src_ip, []).count("PORT_SCAN")
        if syn_count < 3:
            correlate(src_ip, "PORT_SCAN")

# =============================
# Summary report
# =============================
def print_summary():
    print("\n========== SECURITY SUMMARY ==========")
    for ip, score in host_risk.items():
        if score >= ALERT_THRESHOLD:
            print(f"High Risk Host: {ip}")
            print(f"  Risk Score: {score}")
            print(f"  Events: {host_events[ip]}")
            print("----------------------------------")
    print("=====================================\n")

# =============================
# Main
# =============================
if __name__ == "__main__":
    print("=====================================")
    print(" Phase 3 Network IDS – Started ")
    print(" Interface:", INTERFACE)
    print(" Auto Block:", AUTO_BLOCK)
    print("=====================================\n")

    try:
        sniff(iface=INTERFACE, prn=analyze_packet, store=False)
    except KeyboardInterrupt:
        print_summary()
        print("[+] IDS stopped safely")
