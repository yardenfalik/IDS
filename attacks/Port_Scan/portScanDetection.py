from scapy.all import *
from scapy.layers.inet import *
import time

ip_and_ports = {}
request_times = {}

timeout_threshold = 3

returnString = ""

def detectPortScan(packet):
    global ip_and_ports
    global request_times
    global returnString

    cur_time = time.time()

    ip = packet.getlayer(IP)

    if ip.src in ip_and_ports:
        if packet[TCP].dport not in ip_and_ports[ip.src]:
            ip_and_ports[ip.src].append(packet[TCP].dport)

        last_time = request_times[ip.src]
        if (cur_time - last_time) < timeout_threshold:
            if len(ip_and_ports[ip.src]) > 5:
                returnString = f"Port scanning detected from IP: {ip.src}"
                return True
    else:
        ip_and_ports[ip.src] = []
        ip_and_ports[ip.src].append(packet[TCP].dport)
    request_times[ip.src] = cur_time

def tcpFilter(packet):
    return packet.haslayer(TCP) and packet[TCP].flags == "S"

def detectMain(iface, return_dict):
    print("Detecting Port Scan attack...")
    sniff(iface=iface, stop_filter=detectPortScan, lfilter=tcpFilter)
    return_dict[0] = returnString