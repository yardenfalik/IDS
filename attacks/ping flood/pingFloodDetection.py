from scapy.layers.inet import IP, TCP, ICMP
from scapy.packet import Raw
from scapy.sendrecv import send, sniff
import scapy.all as scapy

iface = "VMware Virtual Ethernet Adapter for VMnet8"

numOfRequests = 0
treshold = 100
bad_ips = []

def icmp_packet_callback(packet):
    global numOfRequests
    if ICMP in packet and packet[ICMP].type == 8:  # ICMP Echo Request (ping)
        numOfRequests += 1

    if(numOfRequests > treshold):
        if packet[IP].src not in bad_ips:
            bad_ips.append(packet[IP].src)
            print("Ping flood detected from", packet[IP].src)
        numOfRequests = 0

# Adjust the filter and iface parameters as needed
sniff(filter="icmp", prn=icmp_packet_callback, store=0 , iface=iface)
