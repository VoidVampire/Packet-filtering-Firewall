# 🛡️ PyFirewall - Packet Filtering Firewall

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Scapy-2.6-orange?style=for-the-badge&logo=python)](https://scapy.net/)
[![SQLite](https://img.shields.io/badge/SQLite-3.46-blue?style=for-the-badge&logo=sqlite)](https://www.sqlite.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-Compatible-purple?style=for-the-badge&logo=kali-linux)](https://www.kali.org/)

A powerful Python-based packet filtering firewall with advanced security features, including IP spoofing detection, flood protection, intrusion prevention, and country-based blocking.

![PyFirewall Architecture](https://via.placeholder.com/800x400?text=PyFirewall+Architecture)

## ✨ Features

- 🔍 **Deep Packet Inspection** - Analyze network packets in real-time
- 🛑 **Rule-Based Filtering** - Configure custom allow/block rules with YAML
- 🕵️ **IP Spoofing Detection** - Identify and block spoofed packets with confidence scoring
- 🌊 **Flood Protection** - Prevent SYN and ICMP flood attacks
- 🦠 **Malware Detection** - Scan packets for known malicious signatures
- 🚫 **Geolocation Blocking** - Block traffic from specific countries
- 🔄 **IPTables Integration** - Apply rules directly to Linux kernel firewall
- 📊 **Detailed Logging** - Comprehensive SQLite database for packet analysis

## 🚀 Quick Start

### Prerequisites

```bash
# Install required dependencies
sudo apt-get update
sudo apt-get install -y python3-pip python3-scapy libpcap-dev
pip3 install pyyaml scapy requests ipaddress
```

### Installation

```bash
# Clone the repository
git clone https://github.com/VoidVampire/pyfirewall.git
cd pyfirewall
```

## 📝 Configuration

The firewall is configured through the `firewall_config.yaml` file:

```yaml
db_path: firewall.db
rules:
  - action: block
    protocol: 6  # TCP
    dst_port: 10000  # Block TCP port 10000
  - action: allow
    protocol: 1  # ICMP
    src_ip: 192.168.137.131  # Allow this specific IP
  # Add more rules as needed
    
blocked_countries:
  - xx
  - x
```

## 🏗️ Architecture

PyFirewall consists of several modular components:

| Module | Description |
|--------|-------------|
| `firewall.py` | Core firewall functionality and packet processing |
| `rule_engine.py` | Rule parsing and matching logic |
| `spoof_detection.py` | Advanced IP spoofing detection algorithms |
| `flood_protection.py` | DDoS and flood attack prevention |
| `antivirus.py` | Malicious signature detection in packets |
| `config_loader.py` | YAML configuration parser |

## 💻 Usage

### Basic Operation

```bash
# Start the firewall with default configuration
sudo python3 main.py

# Monitor the logs
sqlite3 firewall.db "SELECT * FROM packet_logs ORDER BY timestamp DESC LIMIT 10;"
```

### Adding Custom Rules

1. Edit `firewall_config.yaml` to add your rules
2. Restart the firewall for changes to take effect

### Viewing Detected Spoofed Packets

```bash
sqlite3 firewall.db "SELECT * FROM detailed_spoof_logs ORDER BY timestamp DESC;"
```

## 🔍 Spoofing Detection

The system uses multiple techniques to detect IP spoofing:

- TTL-based anomaly detection
- Source routing analysis
- Private IP validation
- Network origin verification

Each detection method contributes to a confidence score that determines if a packet is spoofed.

## 🛡️ Security Features

### Flood Protection

```python
# Configurable thresholds
max_connections_per_ip = 3
syn_timeout = 5  # seconds
icmp_timeout = 5  # seconds
```

### Country Blocking

Traffic from specified countries can be automatically blocked by adding country codes to the `blocked_countries` section in the config file.

## 📈 Performance Considerations

- For high-traffic environments, consider adjusting the flood protection thresholds
- Database cleanup is performed periodically to prevent excessive growth
- Consider using PyPy for improved performance on long-running instances


## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.