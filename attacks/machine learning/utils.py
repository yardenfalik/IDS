from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.dhcp import *
from scapy.layers.http import *

def phraseDataset(fileName):
    DHCP_DISCOVER_TYPE = 1
    DHCP_REQUEST_TYPE = 3
    DHCP_OFFER_TYPE = 2
    DHCP_ACKNOWLEDGE_TYPE = 5

    dataSet = PcapReader(fileName)

    syn_count = 0
    ack_count = 0
    dhcpOffer_count = 0
    dhcpDiscover_count = 0
    numberOfPackets = 0
    same_ip = {}
    sameIpForDict = 0
    numberOfDiffrentPorts = 0
    numberOfTcpPackets = 0
    numberOfHttpRequets = 0

    ports = {}

    dict = []
    lenDict = 6

    numFiles = 2

    for packet in dataSet:
        if numberOfPackets < 1000:
            numberOfPackets += 1
            if packet.haslayer(IP) and packet.haslayer(TCP):
                numberOfTcpPackets += 1
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
                
                if(tcp_layer.dport in ports):
                    ports[tcp_layer.dport] += 1
                else:
                    ports[tcp_layer.dport] = 1
   
                if(len(ports) > 1):
                    numberOfDiffrentPorts = len(ports)

            if packet.haslayer(HTTPRequest):
                numberOfHttpRequets += 1
            
            if DHCP in packet and packet[DHCP].options[0][1] == DHCP_OFFER_TYPE:
                dhcpOffer_count += 1
            if DHCP in packet and packet[DHCP].options[0][1] == DHCP_DISCOVER_TYPE:
                dhcpDiscover_count += 1

    for i in same_ip:
        if same_ip[i] > 1:
            sameIpForDict += 1

    return [numberOfPackets, syn_count, ack_count, dhcpOffer_count, dhcpDiscover_count, numberOfDiffrentPorts, numberOfTcpPackets, numberOfHttpRequets]