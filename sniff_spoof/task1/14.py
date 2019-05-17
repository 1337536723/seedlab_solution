#!/bin/bin/python

from scapy.all import *
from datetime import datetime

# remove duplication
# {"hash code":[timestamp, seq]}
seqs = {} 

def reply(pkt):
    global seqs
    key = hash(pkt[IP].src + pkt[IP].dst)
    now = datetime.now().timestamp()
    if key in seqs:
        if seqs[key][0] > now - 30 and seqs[key][1] == pkt[ICMP].seq:
            return
    seqs[key] = [now, pkt[ICMP].seq]
    a = IP() # exchange the src and dst
    a.dst = pkt[IP].src
    a.src = pkt[IP].dst
    b = ICMP() # copy important arguments
    b.type = 0
    b.id = pkt[ICMP].id
    b.seq = pkt[ICMP].seq
    c = Raw() # match the size
    c.load = pkt[Raw].load
    p = a/b/c
    send(p, verbose=0)

pkt=sniff(filter='icmp',prn=reply)