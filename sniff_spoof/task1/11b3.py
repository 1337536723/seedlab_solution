#!/bin/bin/python

from scapy.all import *

def print_pkt(pkt):
	pkt.show()

pkt=sniff(filter='net 10.131.250',prn=print_pkt)
# pkt=sniff(filter='net 10.131.250.0/24',prn=print_pkt)
