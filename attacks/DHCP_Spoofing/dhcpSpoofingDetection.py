from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.dhcp import *

DHCP_DISCOVER_TYPE = 1
DHCP_REQUEST_TYPE = 3
DHCP_OFFER_TYPE = 2
DHCP_ACKNOWLEDGE_TYPE = 5

ips = []

returnString = ""

def detect_dhcp_spoofing(packet):
    print(".")
    global returnString

    if DHCP in packet and packet[DHCP].options[0][1] == DHCP_OFFER_TYPE:
        ips.append(packet[IP].src)
    
    if(len(ips) > 1):
        returnString = f"DHCP Spoofing detected!"
        ips.clear()
        return True

def detectMain(iface, return_dict):
    print("Detecting DHCP Spoofing attack...")
    sniff(filter="udp and (port 67 or 68)", iface=iface, stop_filter=detect_dhcp_spoofing)
    return_dict[0] = returnString