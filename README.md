# NetWatch

**NetWatch** is a Python-based **network traffic monitoring and intrusion detection tool**.  
It captures network packets, analyzes traffic, detects suspicious activity, and provides a **real-time web dashboard**.  

Inspired by tools like **nmap, Wireshark, and Metasploit**, NetWatch is designed for security enthusiasts, pentesters, and network administrators.

---

## Features

- Real-time packet sniffing (TCP, UDP, ICMP, ARP)
- Detection of **suspicious ports and protocols**
  - FTP, Telnet, SMB, RDP, SSH
- Alerts for:
  - Port scanning
  - SSH brute force attempts
  - ICMP flood attacks
  - Unusual DNS activity
- **Risk scoring system** based on activity severity
- Real-time **web dashboard** using Flask
- Logs traffic and alerts in structured format

---

## Requirements

- Python 3.10+  
- Linux (recommended)  
- Packages:
  ```bash
  pip install scapy flask 
