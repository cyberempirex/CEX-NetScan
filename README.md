
# 🔍 CEX-NetScan Professional

    

Professional Network Security Scanner for Termux, Linux & Windows
Real scanning. No fabricated data. Environment-aware intelligence.


---

# 📌 What is CEX-NetScan?

CEX-NetScan is a professional-grade network reconnaissance and security assessment tool built for:

Ethical hackers

Cybersecurity learners

Network administrators

Security researchers


The tool is designed with one strict rule:

> If data cannot be verified, it is not shown.



Unlike many “script scanners” that simulate results, CEX-NetScan only reports what the operating system and network truly allow.


---

# 🎯 Core Design Philosophy

❌ What CEX-NetScan Refuses to Do

❌ Fake device discovery

❌ Guess MAC vendors

❌ Simulate open ports

❌ Claim impossible scans on CGNAT/mobile networks

❌ Hide limitations


### ✅ What CEX-NetScan Guarantees

✅ Real TCP-level scanning

✅ Honest environment detection

✅ Transparent capability limits

✅ Clear accuracy indicators

✅ Ethical-first behavior


> If a scan is not possible, the tool explains why — instead of lying.




---

### 🧠 Intelligence-Driven Architecture

CEX-NetScan adapts itself based on:

Operating system

Root / admin privileges

Network type (WiFi, Mobile CGNAT, VPN, Offline)

Available interfaces

Routing visibility


This prevents invalid scans and misleading output.


---

### 🛡️ Core Capabilities

🔎 Environment & Network Awareness

Capability	Description

OS Detection	Linux, Termux, Windows
Privilege Detection	Root / Non-root
Network Type	WiFi, Mobile CGNAT, VPN
Interface Mapping	All active interfaces
Accuracy Indicators	Confidence labels per scan



---

### 🌐 Network Discovery

Feature	Status	Notes

ARP Scan	Limited	Requires root + LAN
Ping Sweep	Supported	ICMP-based
CGNAT Detection	Supported	Mobile networks
LAN Device Listing	Adaptive	Real responses only



---

### 🔓 Port Scanning

Feature	Supported

TCP Connect Scan	✅
Custom Port Ranges	✅
Service Detection	✅
Stealth SYN Scan	❌ (by design)
UDP Scanning	❌ (planned)


> TCP connect scanning is chosen for stability and legality.




---

### 🧪 Network Analysis

Interface inspection

Local IP detection

Routing visibility

DNS resolution

Connectivity status



---

### 🎨 User Experience Principles

Clean terminal UI

Adaptive colors (not aggressive red/green)

Progress indicators

Educational warnings

Clear menus


Designed to be usable on low-resource devices, including Android phones.


---

### 📁 Project Structure
```text
cex-netscan/
├── core/          # Environment & network detection
│   ├── environment.py
│   ├── network_detect.py
│   ├── connectivity.py
│   └── permissions.py
│
├── scans/         # Real scanning engines
│   ├── arp_scan.py
│   ├── lan_discovery.py
│   ├── ping_scan.py
│   ├── port_scan.py
│   ├── service_fingerprint.py
│   └── route_info.py
│
├── ui/            # Terminal UI
│   ├── menus.py
│   ├── colors.py
│   ├── animations.py
│   ├── warnings.py
│   └── banner.py
│
├── utils/         # Utilities
│   ├── logger.py
│   ├── exporter.py
│   ├── updater.py
│   └── validator.py
│
├── cex_netscan.py
├── requirements.txt
├── config.json
└── README.md


```
### 🚀 Installation Guide

### 📱 Termux (Android)
```pkg update && pkg upgrade -y
pkg install python git nmap netdiscover -y
pip install --upgrade pip
pip install requests netifaces
git clone https://github.com/cyberempirex/cex-netscan.git
cd cex-netscan
python cex_netscan.py
```
### 🐧 Linux
```sudo apt update
sudo apt install python3 python3-pip git nmap netdiscover -y
pip3 install requests netifaces
git clone https://github.com/cyberempirex/cex-netscan.git
cd cex-netscan
python3 cex_netscan.py
```
### ⌛ Windows

1. Install Python 3.6+

2. Install Nmap

3. Add Nmap to PATH

```git clone https://github.com/cyberempirex/cex-netscan.git
cd cex-netscan
pip install -r requirements.txt
python cex_netscan.py
```

### 🎮 Usage Examples
```
python cex_netscan.py --quick
python cex_netscan.py --target 192.168.1.1
python cex_netscan.py --ports 1-1000
python cex_netscan.py --no-color

```
### ⚠️ Platform Limitations

Platform        LAN Discovery     Reason
WiFi            ✅ Yes            Full visibility
Mobile Data     ❌ No             CGNAT isolation
VPN             ⚠️ Depends        Routing rules
Offline         ❌ No             No network

CEX-NetScan will never fake LAN devices on mobile networks.


---

🔒 Ethical Usage Policy

Allowed:
- Your own network
- Authorized corporate testing
- Educational labs
- Research environments

Forbidden:
- Scanning without permission
- Attacking systems
- Surveillance
- Illegal reconnaissance

You are responsible for compliance with local laws.


---

### 🧭 Roadmap

Version 2.x
- Improved exports
- Faster scanning logic
- Better mobile awareness

Version 3.0
- Web-based UI
- Plugin system
- Continuous monitoring


---

### 🤝 Contributing

Contributions are welcome only if they respect the **No Fake Data** rule.

- Clear logic
- Defensive coding
- Cross-platform testing
- Honest documentation


---

### 📄 License

MIT License  
© CyberEmpireX  
Free for personal and commercial use.


---

### 🌐 Community

GitHub: https://github.com/cyberempirex  
Telegram: https://t.me/CyberEmpireXChat  
Website: https://cyberempirex.com


---

CEX-NetScan exists to teach truth — not to impress with lies.
>stay safe,stay secure 
