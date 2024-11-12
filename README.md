# Packet Filtering Firewall

The Packet Filtering Firewall is a comprehensive network security solution developed by Yash Singh, Chris Boban, and Lokesh Bhargava. It is designed to protect your network from various threats, including packet spoofing, flood attacks, malware attacks and supports geo-blocking.

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Contribution](#contribution)
- [License](#license)

## Introduction
The Packet Filtering Firewall is an open-source project that provides a powerful and customizable firewall solution. It combines various security mechanisms, such as rule-based filtering, flood protection, spoofing detection, and malware scanning, to ensure the integrity and safety of your network traffic.

## Features
- **Rule-based Packet Filtering**: Implement custom firewall rules to allow or block traffic based on various criteria, including protocol, source/destination IP, and source/destination ports.
- **Flood Protection**: Detect and mitigate SYN floods and ICMP floods to protect against DDoS attacks.
- **Spoofing Detection**: Identify and log potentially spoofed packets based on various heuristics, such as invalid source IPs, private IPs from untrusted networks, and TTL anomalies.
- **Antivirus Scanning**: Scan incoming packets for known malware signatures to prevent the introduction of malicious code into your network.
- **Geo Blocking**: Analyze packet to detect country-based blocking mechanism using an external IP geolocation API.
- **Logging and Reporting**: Maintain a detailed log of all packet activities, including blocked and allowed packets, as well as identified threats.

## Installation
To set up the Packet Filtering Firewall, follow these steps:

1. Clone the repository:
```
git clone https://github.com/VoidVampire/Packet-filtering-Firewall.git
```
2. Install the required dependencies:
```
pip install -r requirements.txt
```
3. Configure the firewall settings in the `firewall_config.yaml` file.
4. Run the firewall:
```
python main.py
```

## Configuration
The firewall's behavior can be customized by editing the `firewall_config.yaml` file. This file allows you to set the following parameters:

- `db_path`: The path to the SQLite database file used for logging packet information.
- `rules`: A list of firewall rules, each with attributes such as action, protocol, source IP, source port, destination IP, and destination port.

## Usage
Once the firewall is running, it will start capturing and processing network packets according to the defined rules and security mechanisms. You can monitor the firewall's activity by checking the SQLite database or the console output.
