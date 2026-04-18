# 🌐 Network Traffic Analyzer

A Python-based network traffic analyzer built using Scapy.
Captures and logs live network packets in real time.

## 👨‍💻 Author
**Pujan Rasaili** | BSc Software Engineering | University of Bedfordshire

## 🚀 Features
- Captures live TCP, UDP, ICMP packets
- Displays source/destination IP and ports
- Color-coded output by protocol
- Saves all captured packets to CSV log file

## 🛠️ Technologies Used
- Python 3.13
- Scapy 2.7.0
- Colorama

## ⚙️ Requirements
- Windows with Npcap installed
- Python 3.x

## 📦 Installation
```bash
pip install -r requirements.txt
```

## ▶️ Usage
```bash
python analyzer.py
```
Press `CTRL+C` to stop capturing.

## 📁 Output
Logs saved to `logs/traffic_log.csv`