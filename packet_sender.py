from scapy.all import Ether, IP, TCP, Raw, send, conf
import random

# Set network interface
conf.iface = "Ethernet"

def send_nimda_packet(target_ip, target_port=8080, source_ip="192.168.1.1", source_port=12345):
    # Creating the packet with source and destination IPs and ports
    packet = (
        IP(src=source_ip, dst=target_ip) /  # Source and destination IPs
        TCP(sport=source_port, dport=target_port, flags="S", seq=random.randint(1000, 9999)) /  # TCP SYN with random sequence number
        Raw(load="GET /scripts/root.exe HTTP/1.0\r\nHost: example.com\r\n\r\n")  # Raw HTTP payload
    )

    # Send the packet and wait for a response
    send(packet, verbose=True)

if __name__ == "__main__":
    target_ip = "192.168.x.x"  # Replace with your VM's IP
    send_nimda_packet(target_ip)

