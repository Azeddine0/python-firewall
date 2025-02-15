firewall.py - A network monitoring and firewall script that detects and blocks malicious traffic. It can identify known threats (e.g., Nimda worm, Slammer, SSH brute force), block high-traffic IPs, and maintain a whitelist/blacklist. Works on Windows and Linux with iptables or Windows Firewall rules.

packet_sender.py - A Scapy-based script that sends a TCP SYN packet with a raw HTTP GET request, simulating an attack attempt. Useful for testing network security or intrusion detection systems.

simple-packet_sender.py - A minimal script that sends an ICMP (ping) request using Scapy. Good for testing basic network connectivity between the host and a target machine.
