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

class BindInfo():
    def __init__(self):
        # interface
        self.iface = get_if()
        # establish link 
        self.estLink = []

    def established(self,pkt):
        node = [pkt[IP].src, pkt[TCP].sport]
        if node not in self.estLink:
            self.estLink.append(node)
            #print self.estLink
        return

    def handle_pkt(self,pkt):
        if IP in pkt and TCP in pkt :
            print "got a packet"
            pkt.show2()
            #sys.stdout.flush()
            node = [pkt[IP].src, pkt[TCP].sport]
            if node in self.estLink:
                self.recv_data(pkt)
            else:
                if pkt[TCP].flags == 0b000010: # syn
                    return self.send_synack(pkt)
                elif pkt[TCP].flags == 0b010000: # ack
                    return self.established(pkt)

    def send_synack(self,pkt):
        l2 = Ether(src=get_if_hwaddr(self.iface), dst=pkt[Ether].src)
        synack = l2 / IP(dst=pkt[IP].src) / TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport,flags='SA',ack=pkt[TCP].seq + 1, seq=200)
        print "send syn/ack pkt"
        synack.show2()
        sendp(synack)
        sniff(iface = self.iface,prn = lambda x: self.handle_pkt(x))

    def recv_data(self,pkt):
        if Raw in pkt:
            print "got a message %s" % pkt[Raw].load
        return

def main():
    bindinfo = BindInfo()
    print "sniffing on %s" % bindinfo.iface
    #sys.stdout.flush()
    sniff(iface = bindinfo.iface,prn = lambda x: bindinfo.handle_pkt(x))

if __name__ == '__main__':
    main()
