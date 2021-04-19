#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import sniff, send, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw, Ether
from scapy.layers.inet import _IPOption_HDR

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

# interface
iface = get_if()

# establish link 
estLink = []

def handle_pkt(pkt):
    if IP in pkt and TCP in pkt :
        print "got a packet"
        pkt.show2()
        sys.stdout.flush()
        node = [pkt[IP].src, pkt[TCP].sport]
        if node in estLink:
            recv_data(pkt)
        else:
            if pkt[TCP].flags == 0b000010: # syn
                return send_synack(pkt)
            elif pkt[TCP].flags == 0b010000: # ack
                return established(pkt)

def send_synack(pkt):
    l2 = Ether(src=get_if_hwaddr(iface), dst=pkt[Ether].src)
    synack = l2 / IP(dst=pkt[IP].src) / TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport,flags='SA',ack=pkt[TCP].seq + 1, seq=200)
    print "send syn/ack pkt"
    synack.show2()
    sendp(synack)
    sniff(iface = iface,prn = lambda x: handle_pkt(x))

def established(pkt):
    node = [pkt[IP].src, pkt[TCP].sport]
    if node not in estLink:
        estLink.append(node)
        print estLink
    return

def recv_data(pkt):
    if Raw in pkt:
        print "got a message %s" % pkt[Raw].load
    return

def main():
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
