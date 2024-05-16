from flask import redirect, Blueprint, render_template, request, flash
import multiprocessing
import time
import threading

import attacks.Slowloris.slowlorisDetection as sl
import attacks.Http_Flood.httpFloodDetection as hf
import attacks.DHCP_Starvation.DHCPStarvationDetection as ds
import attacks.Port_Scan.portScanDetection as ps
import attacks.DHCP_Spoofing.dhcpSpoofingDetection as dsp

detection = Blueprint('detection', __name__)

@detection.route('/slowLoris', methods=['GET', 'POST'])
def slowLoris():
    manager = multiprocessing.Manager()
    return_dict = manager.dict()

    if request.method == 'POST': 
        iface = request.form.get('iface') # Gets the ip from the HTML

        p = multiprocessing.Process(target=sl.detectMain, args=(iface, return_dict))
        p.start()
        p.join()

        flash("SlowLoris Detection has ended")
        flash(str(return_dict[0]))

    return render_template("ifaceDetection.html", detection="SlowLoris Detection")

@detection.route('/httpFlood', methods=['GET', 'POST'])
def httpFlood():
    manager = multiprocessing.Manager()
    return_dict = manager.dict()

    if request.method == 'POST': 
        iface = request.form.get('iface') # Gets the ip from the HTML

        p = multiprocessing.Process(target=hf.detectMain, args=(iface, return_dict))
        p.start()
        p.join()

        flash("HTTP Flood Detection has ended!")
        flash(str(return_dict[0]))
        
    return render_template("ifaceDetection.html", detection="HTTP Flood Detection")

@detection.route('/DHCPStarvation', methods=['GET', 'POST'])
def DHCPStarvation():
    manager = multiprocessing.Manager()
    return_dict = manager.dict()

    if request.method == 'POST': 
        iface = request.form.get('iface') # Gets the ip from the HTML

        p = multiprocessing.Process(target=ds.detectMain, args=(iface, return_dict))
        p.start()
        p.join()

        flash("DHCP Starvation Detection has ended!")
        flash(str(return_dict[0]))
        
    return render_template("ifaceDetection.html", detection="DHCP Starvation Detection")

@detection.route('/portScan', methods=['GET', 'POST'])
def portScan():
    manager = multiprocessing.Manager()
    return_dict = manager.dict()

    if request.method == 'POST': 
        iface = request.form.get('iface') # Gets the ip from the HTML

        p = multiprocessing.Process(target=ps.detectMain, args=(iface, return_dict))
        p.start()
        p.join()

        flash("port Scan Detection has ended!")
        flash(str(return_dict[0]))
        
    return render_template("ifaceDetection.html", detection="port Scan Detection")

@detection.route('/DHCPSpoofing', methods=['GET', 'POST'])
def DHCPSpoofing():
    manager = multiprocessing.Manager()
    return_dict = manager.dict()

    if request.method == 'POST': 
        iface = request.form.get('iface') # Gets the ip from the HTML

        p = multiprocessing.Process(target=dsp.detectMain, args=(iface, return_dict))
        p.start()
        p.join()

        flash("DHCP Spoofing Detection has ended!")
        flash(str(return_dict[0]))
        
    return render_template("ifaceDetection.html", detection="DHCP Spoofing Detection")