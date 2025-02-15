from scapy.all import IP, ICMP, send

target_ip = "192.168.x.x"  # Replace with your VM’s actual IP
packet = IP(dst=target_ip) / ICMP()
send(packet, verbose=True)
