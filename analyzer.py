import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from colorama import Fore, Style, init
from datetime import datetime
import csv
import os

# Initialize colorama
init(autoreset=True)

LOG_FILE = "logs/traffic_log.csv"
packet_count = 0

def setup_log():
    os.makedirs("logs", exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Time", "Protocol", "Source IP", "Destination IP", "Source Port", "Dest Port", "Size"])

def get_protocol(packet):
    if packet.haslayer(TCP):
        return "TCP", Fore.GREEN
    elif packet.haslayer(UDP):
        return "UDP", Fore.YELLOW
    elif packet.haslayer(ICMP):
        return "ICMP", Fore.CYAN
    else:
        return "OTHER", Fore.WHITE

def process_packet(packet):
    global packet_count
    if packet.haslayer(IP):
        packet_count += 1
        protocol, color = get_protocol(packet)
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        size = len(packet)
        time = datetime.now().strftime("%H:%M:%S")

        src_port = dst_port = "-"
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        print(f"{color}[{time}] {protocol:<5} | {src_ip}:{src_port} → {dst_ip}:{dst_port} | Size: {size} bytes")

        with open(LOG_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([time, protocol, src_ip, dst_ip, src_port, dst_port, size])

def start_sniffing():
    setup_log()
    print(Fore.MAGENTA + "=" * 60)
    print(Fore.MAGENTA + "   NETWORK TRAFFIC ANALYZER")
    print(Fore.MAGENTA + "   By: Pujan Rasaili | Bedfordshire University")
    print(Fore.MAGENTA + "=" * 60)
    print(Fore.WHITE + "   Capturing packets... Press CTRL+C to stop\n")
    try:
        scapy.sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Stopped! Total packets captured: {packet_count}")
        print(Fore.YELLOW + f"Log saved to: {LOG_FILE}")

if __name__ == "__main__":
    start_sniffing()