from scapy.all import *
from scapy.layers.inet import *

def scan_port(ip, return_dict, start_port=1, end_port=1000):
    openPorts = []

    for port in range(start_port, end_port + 1):
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
    
        if response is not None and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            print(f"Port {port} is open")

            openPorts.append(port)

            packet = IP(dst=ip) / TCP(dport=port, flags="R")
            response = sr1(packet, timeout=1, verbose=0)
    
    return_dict[0] = openPorts