from scapy.all import sniff, IP, TCP
from datetime import datetime, timedelta
import os

# =============================
# Config
# =============================
INTERFACE = "eth0"
LOG_FILE = "alerts.log"
ALERT_THRESHOLD = 7       # Risk score threshold
ALERT_INTERVAL = 5        # seconds, avoid flooding

RISK_SCORES = {
    "TELNET": 5,
    "FTP": 4,
    "HTTP": 2,
    "SSH_WEAK": 3,
    "PORT_SCAN": 4
}

host_events = {}
host_risk = {}
last_alert_time = {}   # track last alert to avoid spam

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
    if src_ip not in host_events:
        host_events[src_ip] = []
        host_risk[src_ip] = 0
        last_alert_time[src_ip] = datetime.min

    host_events[src_ip].append(event)
    host_risk[src_ip] += RISK_SCORES.get(event, 0)

    # Only alert if last alert > ALERT_INTERVAL seconds ago
    now = datetime.now()
    if (now - last_alert_time[src_ip]).total_seconds() >= ALERT_INTERVAL:
        if host_risk[src_ip] >= ALERT_THRESHOLD:
            log_alert(f"[CRITICAL] {src_ip} | Risk Score: {host_risk[src_ip]} | Events: {host_events[src_ip]}")
        else:
            log_alert(f"[INFO] {src_ip} | Risk Score: {host_risk[src_ip]} | Events: {host_events[src_ip]}")
        last_alert_time[src_ip] = now

# =============================
# Packet analysis
# =============================
def analyze_packet(packet):
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    src_ip = packet[IP].src
    dst_port = packet[TCP].dport

    if dst_port == 23:
        correlate(src_ip, "TELNET")
    elif dst_port == 21:
        correlate(src_ip, "FTP")
    elif dst_port == 80:
        correlate(src_ip, "HTTP")

    if packet[TCP].flags == "S":
        correlate(src_ip, "PORT_SCAN")

# =============================
# Summary
# =============================
def print_summary():
    print("\n========== SECURITY SUMMARY ==========")
    for ip, score in host_risk.items():
        risk = "HIGH" if score >= ALERT_THRESHOLD else "MEDIUM"
        print(f"Host: {ip}")
        print(f"  Risk: {risk} ({score})")
        print(f"  Events: {', '.join(host_events[ip])}")
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
