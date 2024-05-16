from flask import redirect, Blueprint, render_template, request, flash
import multiprocessing
import time
import threading

import attacks.Http_Flood.httpFlood as hf
import attacks.Port_Scan.portScan as ps
import attacks.Slowloris.slowloris as sl
import attacks.DHCP_Starvation.DHCPStarvation as ds
import attacks.syn_ping_flood.synPingFlood as spf
import attacks.DHCP_Spoofing.dhcpSpoofing as dsp

attack = Blueprint('attack', __name__)

@attack.route('/tcpSynFlood', methods=['GET', 'POST'])
def tcpSynFlood():
    if request.method == 'POST': 
        ip = request.form.get('ip') # Gets the ip from the HTML 
        timer = request.form.get('time') # Gets the time from the HTML

        p = multiprocessing.Process(target=spf.synFlood, args=(ip,))
        p.start()
        time.sleep(int(timer))
        p.terminate()
        p.join()

        flash("TCP SYN Flood Attack has ended!")

    return render_template("ipAndTimeAttacks.html", attack="TCP SYN Flood Attack")

@attack.route('/slowLoris', methods=['GET', 'POST'])
def slowLoris():
    if request.method == 'POST': 
        ip = request.form.get('ip') # Gets the ip from the HTML
        timer = request.form.get('time') # Gets the time from the HTML

        p = multiprocessing.Process(target=sl.slowloris, args=(ip,))
        p.start()
        time.sleep(int(timer))
        p.terminate()
        p.join()

        flash("SlowLoris Attack has ended!")

    return render_template("ipAndTimeAttacks.html", attack="SlowLoris Attack")

@attack.route('/httpFlood', methods=['GET', 'POST'])
def httpFlood():
    if request.method == 'POST': 
        ip = request.form.get('ip') # Gets the ip from the HTML
        timer = request.form.get('time') # Gets the time from the HTML

        p = multiprocessing.Process(target=hf.httpFlood, args=(ip,))
        p.start()
        time.sleep(int(timer))
        p.terminate()
        p.join()

        flash("HTTP Flood Attack has ended!")
        
    return render_template("ipAndTimeAttacks.html", attack="HTTP Flood Attack")

@attack.route('/portScan', methods=['GET', 'POST'])
def portScan():
    manager = multiprocessing.Manager()
    return_dict = manager.dict()

    if request.method == 'POST': 
        ip = request.form.get('ip') # Gets the ip from the HTML
        end_port = request.form.get('end')
        start_port = request.form.get('start')

        if(start_port == ""):
            start_port = 1
        if(end_port == ""):
            end_port = 1000

        p = multiprocessing.Process(target=ps.scan_port, args=(ip, return_dict, int(start_port), int(end_port),))
        p.start()
        p.join()

        flash("Port Scan Attack has ended")
        flash("Open ports are: " + str(return_dict[0]))

    return render_template("portScanHtml.html", attack="Port Scan Attack")

@attack.route('/DHCPSpoofing', methods=['GET', 'POST'])
def DHCPSpoofing():
    manager = multiprocessing.Manager()
    return_dict = manager.dict()

    if request.method == 'POST': 
        iface = request.form.get('iface') # Gets the ip from the HTML
        gateway_ip = request.form.get('gateway')
        computer_mac = request.form.get('realMac')
        subnet_mask = request.form.get('mask')
        dns_server_ip = request.form.get('dns')
        router_mac = request.form.get('routerMac')
        router_ip = request.form.get('routerIp')

        p = multiprocessing.Process(target=dsp.spoof, args=(return_dict, iface, gateway_ip, computer_mac, subnet_mask, dns_server_ip, router_mac, router_ip))
        p.start()
        p.join()

        flash("DHCP Spoofing Attack has ended")
        flash(str(return_dict[0]))

    return render_template("dhcpSpoofing.html", attack="DHCP Spoofing Attack")

@attack.route('/DHCPStarvation', methods=['GET', 'POST'])
def starvation():
    if request.method == 'POST': 
        iface = request.form.get('iface') # Gets the ip from the HTML
        timer = request.form.get('time')

        p = multiprocessing.Process(target=ds.dhcp_starvation, args=(iface,))
        p.start()
        time.sleep(int(timer))
        p.terminate()
        p.join()

        flash("DHCP Starvation has ended")

    return render_template("ifaceAttacks.html", attack="DHCP Starvation Attack")

@attack.route('/pingFlood', methods=['GET', 'POST'])
def pingFlood():
    if request.method == 'POST': 
        ip = request.form.get('ip') # Gets the ip from the HTML 
        timer = request.form.get('time') # Gets the time from the HTML

        p = multiprocessing.Process(target=spf.pingFlood, args=(ip,))
        p.start()
        time.sleep(int(timer))
        p.terminate()
        p.join()

        flash("Ping Flood Attack has ended!")

    return render_template("ipAndTimeAttacks.html", attack="Ping Attack")