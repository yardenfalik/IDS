from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import *
import time

request_times = {}

returnString = ""

def detect_slowloris(packet):
    print(".")

    global request_times
    global returnString

    #==Changeable Params==
    timeout_threshold = 3
    howManyValidFields = 5
    #=====================

    cur_time = time.time()

    http = packet.getlayer(HTTPRequest)
    if(len(http.fields) <= howManyValidFields):
        ip = packet.getlayer(IP)
        if ip.src in request_times: 
            last_time = request_times[ip.src]
            if (cur_time - last_time) < timeout_threshold:
                returnString = f"Slowloris attack detected from {ip.src}"
                return True
        request_times[ip.src] = cur_time
   
def incoming_filter(packet):
    return packet.haslayer(HTTPRequest)

def detectMain(iface, return_dict):
    print("Detecting Slowloris attack...")
    s = sniff(lfilter=incoming_filter, iface=iface, stop_filter=detect_slowloris)
    return_dict[0] = returnString