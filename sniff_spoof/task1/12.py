#!/bin/bin/python

from scapy.all import *

a = IP()
a.src = '10.0.2.6'
a.dst = '10.131.250.58'
b = ICMP()
p = a/b
send(p)