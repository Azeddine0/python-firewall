import os
import sys
import time
import platform
import ctypes
import socket
import threading
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, conf

THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")

# Detect OS
IS_WINDOWS = platform.system() == "Windows"

# Admin check
def is_admin():
    if IS_WINDOWS:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return os.geteuid() == 0  # Linux

if not is_admin():
    print("This script requires administrator/root privileges.")
    sys.exit(1)

# Read IPs from a file
def read_ip_file(filename):
    try:
        with open(filename, "r") as file:
            ips = [line.strip() for line in file]
        return set(ips)
    except FileNotFoundError:
        return set()

# Logging
def log_event(message):
    log_folder = "logs"
    os.makedirs(log_folder, exist_ok=True)
    log_file = os.path.join(log_folder, "network_monitor.log")
    
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    log_entry = f"[{timestamp}] {message}\n"

    with open(log_file, "a") as file:
        file.write(log_entry)
    
    print(log_entry.strip())

# IP Blocking
def block_ip(ip):
    if IS_WINDOWS:
        os.system(f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=in action=block remoteip={ip}")
    else:
        if os.system(f"iptables -C INPUT -s {ip} -j DROP") != 0:
            os.system(f"iptables -I INPUT -s {ip} -j DROP")
    log_event(f"Blocked IP: {ip}")

def unblock_ip(ip):
    if IS_WINDOWS:
        os.system(f"netsh advfirewall firewall delete rule name=\"Block {ip}\" remoteip={ip}")
    else:
        os.system(f"iptables -D INPUT -s {ip} -j DROP")
    log_event(f"Unblocked IP: {ip}")

# Resolve IP to hostname
def resolve_ip(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

# Attack detections
def is_nimda_worm(packet):
    return packet.haslayer(TCP) and packet[TCP].dport == 80 and "GET /scripts/root.exe" in str(packet[TCP].payload)

def detect_slammer(packet):
    return packet.haslayer(UDP) and packet[UDP].sport == 1434 and len(packet[UDP].payload) > 100

def detect_ssh_brute(packet):
    return packet.haslayer(TCP) and packet[TCP].dport == 22

# Packet handling
def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src

    if src_ip in whitelist_ips:
        return

    if src_ip in blacklist_ips:
        block_ip(src_ip)
        return
    
    if is_nimda_worm(packet) or detect_slammer(packet) or detect_ssh_brute(packet):
        log_event(f"Blocking malicious IP: {src_ip}")
        block_ip(src_ip)
        return
    
    packet_count[src_ip] += 1
    current_time = time.time()
    time_interval = current_time - start_time[0]
    
    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                log_event(f"Blocking high-traffic IP: {ip} (Rate: {packet_rate})")
                block_ip(ip)
                blocked_ips.add(ip)
        
        packet_count.clear()
        start_time[0] = current_time

# Interactive command interface
def command_interface():
    while True:
        cmd = input("Enter command (list, unblock <IP>, exit): ").strip()
        if cmd.startswith("unblock"):
            ip = cmd.split()[1]
            unblock_ip(ip)
        elif cmd == "list":
            if IS_WINDOWS:
                os.system("netsh advfirewall firewall show rule name=all")
            else:
                os.system("iptables -L INPUT -v -n")
        elif cmd == "exit":
            print("Exiting...")
            os._exit(0)

if __name__ == "__main__":
    # Load IP lists
    whitelist_ips = read_ip_file("whitelist.txt")
    blacklist_ips = read_ip_file("blacklist.txt")
    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    # Start command interface
    threading.Thread(target=command_interface, daemon=True).start()

    print("Monitoring network traffic...")

    # Set up sniffing
    if IS_WINDOWS:
        conf.use_pcap = True  # Enable pcap for Windows (requires Npcap)
        iface = "Ethernet 2"  # Adjust to your network interface
        sniff(iface=iface, prn=packet_callback, store=0)
    else:
        sniff(filter="ip", prn=packet_callback)
