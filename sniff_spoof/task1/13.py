#!/bin/bin/python

from scapy.all import *

i = 1
a = IP()
b = ICMP()
a.dst = "fudan.edu.cn"

while True:
    a.ttl = i
    p = a/b
    send(p, verbose=0)
    reply = sr1(p, verbose=0)
    if reply is None:
        continue
    reply_src = reply[IP].src
    reply_type = reply[ICMP].type
    reply_code = reply[ICMP].code
    if reply_type == 11 and reply_code == 0:
        print(i, reply_src)
        i += 1
    elif reply_type == 0:
        print(i, reply_src, "<")
        break