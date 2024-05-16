from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import *
import time

ip_and_number_of_requests = {}
request_times = {}

returnString = ""

def detect_HTTP_Flood(packet):
    print(".")

    global ip_and_number_of_requests
    global request_times
    global returnString

    #=======Changeable Params=======
    howManyrequestsAreAllowedInAnInterval = 100
    timeout_threshold = 3
    #===============================

    cur_time = time.time()

    ip = packet.getlayer(IP)
    if ip.src in ip_and_number_of_requests: 
        ip_and_number_of_requests[ip.src] += 1
        last_time = request_times[ip.src]
        if (cur_time - last_time) < timeout_threshold:
            if ip_and_number_of_requests[ip.src] > howManyrequestsAreAllowedInAnInterval:
                returnString = f"HTTP Flood attack detected from {ip.src}"
                return True
    else:
        ip_and_number_of_requests[ip.src] = 1
    request_times[ip.src] = cur_time
    
        
def incoming_filter(packet):
    return packet.haslayer(HTTPRequest)

def detectMain(iface, return_dict):
    print("Detecting Http Flood attack...")
    sniff(lfilter=incoming_filter, iface=iface, stop_filter=detect_HTTP_Flood)
    return_dict[0] = returnString