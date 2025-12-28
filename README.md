# Packet Sniffer in Python

A simple packet sniffing tool written in Python for educational and analysis purposes.

## Overview

This project captures network packets on a given interface (e.g., Kali Linux) and displays
basic information about the packets, such as headers, source/destination, and protocol.

⚠️ **Warning:** Packet sniffing requires administrative privileges (raw sockets).
Only run in environments where you have permission (e.g., your own machine or lab).  
Unauthorized sniffing on networks you do not control may violate laws.

## Features

- Captures live packets from a network interface
- Displays packet summary (protocol, source, destination)
- Easy to run and understand

## Technologies Used

- Python 3
- Scapy (for packet capture and parsing)

## Getting Started

### 1. Clone the repository


 git clone https://github.com/Appiseq/Packet-Sniffing.git
 cd Packet-Sniffing

 pip install -r requirements.txt
 sudo python3 packet_sniffer.py 

Captured TCP Packet from 192.168.1.10 → 172.217.0.46
Protocol: TCP
Length: 74

### Packet sniffers are foundational networking tools used in:
- Network debugging
- Protocol understanding
- Security research (ethical only)





