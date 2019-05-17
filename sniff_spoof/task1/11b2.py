#!/bin/bin/python

from scapy.all import *

def print_pkt(pkt):
	pkt.show()

pkt=sniff(filter='src host 202.120.224.115 && port 80',prn=print_pkt)
