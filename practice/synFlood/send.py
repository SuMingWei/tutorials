#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, sr1 , srp1, sniff
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class TCPHandshake():
    def __init__(self):
        # l2
        self.iface = get_if()
        # l3
        self.addr = "10.0.1.1" # default send to h1
        # l4
        self.dstPort = random.randint(49152,65535)
        self.srcPort = 1234
        self.seqNum = 100
        self.ackNum = 0
        # flag 
        self.established = False

    def start(self):
        print "sending on interface %s to %s" % (self.iface, str(self.addr))
        return self.send_syn()

    def handle_recv(self,pkt):
        if IP in pkt and TCP in pkt:
            print "got pkt"
            pkt.show2()
            if pkt[TCP].dport == self.srcPort and pkt[TCP].ack == self.seqNum:
                if pkt[TCP].flags == 0b010010: # receive syn/ack
                    return self.send_ack(pkt)
                else:
                    print "got other packet"
        return
        
    def send_syn(self):
        l2 = Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff')
        syn = l2 / IP(dst=self.addr) / TCP(dport=self.dstPort, sport=self.srcPort,flags='S',seq=self.seqNum)
        # send syn packet
        print "send syn"
        syn.show2()
        sendp(syn, iface=self.iface, verbose=False)
        self.seqNum += 1
        # received packet from target
        sniff(iface=self.iface,prn = lambda x: self.handle_recv(x),count=1)

    

    def send_ack(self,pkt):
        l2 = Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff')
        ack = l2 / IP(dst=pkt[IP].src) / TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport,flags='A',ack=pkt[TCP].seq + 1, seq=self.seqNum)
        # send ack pkt
        print "send ack"
        ack.show2()
        sendp(ack)
        # received packet from target
        sniff(iface=self.iface,prn = lambda x: self.handle_recv(x),count=1,timeout=1)
        self.established = True

    def send_data(self,mes):
        l2 = Ether(src=get_if_hwaddr(self.iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = l2 / IP(dst=self.addr) / TCP(dport=self.dstPort, sport=self.srcPort,flags='A',seq=self.seqNum) / mes
        # send ack pkt
        print "send data"
        pkt.show2()
        sendp(pkt)

def synFlood():
    l2 = Ether(src=get_if_hwaddr(get_if()), dst='ff:ff:ff:ff:ff:ff')
    syn = l2 / IP(dst="10.0.1.1") / TCP(dport=80, sport=random.randint(49152,65535),flags='S',seq=300)
    # send syn packet
    print "send synFlood"
    sendp(syn, iface=get_if(), verbose=False,loop=1)

def main():
    if len(sys.argv) == 2: 
        if sys.argv[1] == "flood":
            synFlood()
    else:
        tcp_handshake = TCPHandshake()
        print "start hand shaking"
        tcp_handshake.start()
        while(1):
            if(tcp_handshake.established):
                break
            else:
                print "restart hand shaking"
                tcp_handshake.start()
    
        print "handshake finished"
        print "=============================="
        print "send data"
        for i in range(1,4):
            tcp_handshake.send_data(str(i))
    
    

if __name__ == '__main__':
    main()
