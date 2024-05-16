import numpy as np
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.dhcp import *
from scapy.layers.http import *
import DataSetPhrase as dsp
import json 

iface = "VMware Virtual Ethernet Adapter for VMnet8"

numFiles = dsp.NUMBER_OF_DATASETS + 1
lenDict = 6

DHCP_DISCOVER_TYPE = 1
DHCP_REQUEST_TYPE = 3
DHCP_OFFER_TYPE = 2
DHCP_ACKNOWLEDGE_TYPE = 5

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

def packetHandler(packet):
    global syn_count
    global ack_count
    global dhcpOffer_count
    global dhcpDiscover_count
    global numberOfPackets
    global same_ip
    global sameIpForDict
    global numberOfDiffrentPorts
    global numberOfTcpPackets
    global numberOfHttpRequets
    global ports

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

def initData():
    print("init data...\n")
    dataSetsFileName = dsp.Phrase()
    print("datasets are ready!\n")
    return dataSetsFileName

def startSniffing():
    print("start sniffing...\n")
    sniff(prn=packetHandler, iface=iface, store=0, count=1000)

def printResults(minPos):
    print("the best estimation is an: ")
    if (minPos == 0):
        print("DHCP Starvation attack")
    elif (minPos == 1):
        print("DHCP Spoofing attack")
    elif (minPos == 2):
        print("Port Scan attack")
    elif (minPos == 3):
        print("TCP Syn Flood attack")
    elif (minPos == 4 or minPos == 5):
        print("HTTP Flood attack")
    else:  
        print("An eeror has occured!")


def main():
    #dataSetsFileName = initData()

    startSniffing()

    dict = [numberOfPackets, syn_count, ack_count, dhcpOffer_count, dhcpDiscover_count, numberOfDiffrentPorts, numberOfTcpPackets, numberOfHttpRequets]

    data_file = open("data.txt", "r")
    dataSets = json.loads(data_file.read())
    dataSets.append(dict)
    datasetArr = np.array((dataSets))

    #print("arr=\n", datasetArr)

    dist = np.empty((numFiles,numFiles),dtype=float)
    for i in range(0, numFiles): 
        for j in range(0, numFiles):

            arrayDiff = datasetArr[i,:] - datasetArr[j,:]

            arraySqr =  np.square(arrayDiff)
            arraySum =  np.sum(arraySqr)
            dist[i,j] = np.sqrt(arraySum)
    #print("dist=\n", dist)   

    minPos = np.argmin(np.delete(dist[len(dist) - 1], len(dist[len(dist) - 1]) - 1))
    
    printResults(minPos)

if __name__ == "__main__":
    main()