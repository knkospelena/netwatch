#!/usr/bin/env python3
from flask import Flask, render_template_string, jsonify
from scapy.all import sniff, TCP, IP
import threading
import subprocess
import time
from collections import defaultdict

# =====================
# Phase 3 Data Stores
# =====================
host_data = defaultdict(lambda: {
    "events": set(),
    "risk": 0,
    "severity": "LOW"
})

alerts = []
all_traffic = []

EVENT_SCORES = {
    "TELNET": 5,
    "PORT_SCAN": 4
}

# =====================
# Packet Analysis
# =====================
def analyze_packet(pkt):
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        summary = pkt.summary()

        # Store ALL traffic (Wireshark-style)
        all_traffic.append({
            "time": time.strftime("%H:%M:%S"),
            "src": src,
            "dst": dst,
            "proto": proto,
            "summary": summary
        })

        if TCP in pkt:
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport

            # TELNET Detection
            if dport == 23 or sport == 23:
                register_event(src, "TELNET")

            # Simple PORT SCAN detection (SYN packets)
            if pkt[TCP].flags == "S":
                register_event(src, "PORT_SCAN")

def register_event(ip, event):
    if event not in host_data[ip]["events"]:
        host_data[ip]["events"].add(event)
        host_data[ip]["risk"] += EVENT_SCORES[event]
        update_severity(ip)

        alerts.append({
            "time": time.strftime("%H:%M:%S"),
            "ip": ip,
            "event": event,
            "risk": host_data[ip]["risk"],
            "severity": host_data[ip]["severity"]
        })

def update_severity(ip):
    score = host_data[ip]["risk"]
    if score >= 10:
        host_data[ip]["severity"] = "HIGH"
    elif score >= 5:
        host_data[ip]["severity"] = "MEDIUM"
    else:
        host_data[ip]["severity"] = "LOW"

# =====================
# Sniffer Thread
# =====================
def start_sniffer():
    sniff(prn=analyze_packet, store=False)

# =====================
# Flask App
# =====================
app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Phase 3 IDS Dashboard</title>
    <style>
        body { font-family: Arial; background:#111; color:#eee; }
        h1 { color:#00ffcc; }
        table { width:100%; border-collapse: collapse; margin-top:10px;}
        th, td { border:1px solid #333; padding:6px; }
        th { background:#222; }
        .HIGH { color:red; }
        .MEDIUM { color:orange; }
        .LOW { color:lightgreen; }
        button { padding:10px; margin:5px; }
        .tab { display:none; }
    </style>
    <script>
        function showTab(tab) {
            document.getElementById("alerts").style.display="none";
            document.getElementById("traffic").style.display="none";
            document.getElementById(tab).style.display="block";
        }

        async function refresh() {
            const alerts = await fetch('/alerts').then(r=>r.json());
            const traffic = await fetch('/traffic').then(r=>r.json());

            let ahtml="";
            alerts.forEach(a=>{
                ahtml += `<tr>
                    <td>${a.time}</td>
                    <td>${a.ip}</td>
                    <td>${a.event}</td>
                    <td>${a.risk}</td>
                    <td class="${a.severity}">${a.severity}</td>
                </tr>`;
            });
            document.getElementById("alerts_body").innerHTML=ahtml;

            let thtml="";
            traffic.slice(-200).forEach(t=>{
                thtml += `<tr>
                    <td>${t.time}</td>
                    <td>${t.src}</td>
                    <td>${t.dst}</td>
                    <td>${t.proto}</td>
                    <td>${t.summary}</td>
                </tr>`;
            });
            document.getElementById("traffic_body").innerHTML=thtml;
        }

        setInterval(refresh, 2000);
    </script>
</head>
<body onload="showTab('alerts')">

<h1>Phase 3 IDS – Flask GUI</h1>

<button onclick="showTab('alerts')">Alerts & Risk</button>
<button onclick="showTab('traffic')">All Traffic (Wireshark View)</button>

<div id="alerts" class="tab">
<h2>Correlated Alerts</h2>
<table>
<tr>
<th>Time</th><th>Source IP</th><th>Event</th><th>Risk</th><th>Severity</th>
</tr>
<tbody id="alerts_body"></tbody>
</table>
</div>

<div id="traffic" class="tab">
<h2>All Traffic</h2>
<table>
<tr>
<th>Time</th><th>Source</th><th>Destination</th><th>Proto</th><th>Summary</th>
</tr>
<tbody id="traffic_body"></tbody>
</table>
</div>

</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/alerts")
def get_alerts():
    return jsonify(alerts)

@app.route("/traffic")
def get_traffic():
    return jsonify(all_traffic)

# =====================
# Auto-open Browser (Linux-safe)
# =====================
def open_browser():
    time.sleep(2)  # give Flask time to start
    subprocess.Popen(["xdg-open", "http://127.0.0.1:5000"])

# =====================
# Main
# =====================
if __name__ == "__main__":
    print("[+] Starting Phase 3 IDS with Flask GUI")
    threading.Thread(target=start_sniffer, daemon=True).start()
    threading.Thread(target=open_browser, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=False)
