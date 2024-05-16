from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.dhcp import *

import time

iface = ""

DHCP_DISCOVER_TYPE = 1
DHCP_REQUEST_TYPE = 3
DHCP_OFFER_TYPE = 2
DHCP_ACKNOWLEDGE_TYPE = 5

#==Changeable Params==
timeout_threshold = 3
#=====================

timeOfLastRequest = time.time()

returnString = ""

def detect_dhcp_spoofing(packet):

    cur_time = time.time()
    global timeOfLastRequest
    global returnString

    wasAResponse = False

    if DHCP in packet and packet[DHCP].options[0][1] == DHCP_DISCOVER_TYPE:
        last_time = timeOfLastRequest
        if (cur_time - last_time) < timeout_threshold:
            dhcp_discover = Ether(dst='ff:ff:ff:ff:ff:ff',src=RandMAC())  \
                    /IP(src='0.0.0.0',dst='255.255.255.255') \
                    /UDP(sport=68,dport=67) \
                    /BOOTP(op=1,chaddr = RandMAC()) \
                    /DHCP(options=[('message-type','discover'),('end')])

            ans, unans = srp(dhcp_discover, timeout=5, iface=iface, verbose=0)

            for snd,rcv in ans:
                if rcv[DHCP].options[0][1] == DHCP_OFFER_TYPE: # Check if the message type is DHCP OFFER
                    wasAResponse = True

            if wasAResponse == False:
                returnString = f"DHCP Starvation attack detected."
                return True

        timeOfLastRequest = cur_time

def detectMain(ifaceName, return_dict):
    global iface
    iface = ifaceName
    print("Detecting DHCP Starvation attack...")
    sniff(filter="udp and (port 67 or 68)", iface=iface, stop_filter=detect_dhcp_spoofing)
    return_dict[0] = returnString