import re
import numpy as np
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.dhcp import *

DHCP_DISCOVER_TYPE = 1
DHCP_REQUEST_TYPE = 3
DHCP_OFFER_TYPE = 2
DHCP_ACKNOWLEDGE_TYPE = 5

dataSetPath = "capture.pcap"

dataSet = PcapReader(dataSetPath)

syn_count = 0
ack_count = 0
dhcpOffer_count = 0
dhcpDiscover_count = 0
numberOfPackets = 0
same_ip = {}
sameIpForDict = 0

dict = []

for packet in dataSet:
    if numberOfPackets < 1000:
        numberOfPackets += 1
        if packet.haslayer(IP) and packet.haslayer(TCP):
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]

            if tcp_layer.flags & 2:
                syn_count += 1
            
            if ip_layer.src in same_ip:
                same_ip[ip_layer.src] += 1
            else:
                same_ip[ip_layer.src] = 1

            if tcp_layer.flags & 10 and not tcp_layer.flags & 2:
                ack_count += 1
        
        if DHCP in packet and packet[DHCP].options[0][1] == DHCP_OFFER_TYPE:
            dhcpOffer_count += 1
        if DHCP in packet and packet[DHCP].options[0][1] == DHCP_DISCOVER_TYPE:
            dhcpDiscover_count += 1

for i in same_ip:
    if same_ip[i] > 1:
        sameIpForDict += 1

dict = [numberOfPackets, syn_count, ack_count, sameIpForDict, dhcpOffer_count, dhcpDiscover_count]

f = open("dic.txt", "w")
f.write(str(dict))
f.close()