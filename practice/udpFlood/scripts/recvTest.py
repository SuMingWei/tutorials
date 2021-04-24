#!/usr/bin/env python
from scapy.all import *

import datetime
import time
import socket



def packet_sniff(pkt):
    time = datetime.datetime.now()
    
    # using haslayer() to check if the layer exist
    if pkt.haslayer(TCP):
        print("TCP")
        # if pkt dst ip addr == this machine's ip addr -> incoming
        if socket.gethostbyname(socket.gethostname())==pkt[IP].dst:
            print(str("[")+str(time)+str("]")+" "+"TCP-OUT:{}".format(len(pkt[TCP]))+" Bytes"+" "+"Src MAC:"+str(pkt.src)+" "+ "DST-MAC:"+str(pkt.dst)+" "+"SRC-PORT:"+str(pkt.sport)+" "+"DST-PORT:"+str(pkt.dport)+""+"SRC-IP:"+str(pkt[IP].src )+" "+"DST-IP:"+str(pkt[IP].dst )+"\n\n")
        # if pkt src ip addr == this machine's ip addr -> outgoing
        if socket.gethostbyname(socket.gethostname())==pkt[IP].src:
            print(str("[")+str(time)+str("]")+" "+"TCP-IN:{}".format(len(pkt[TCP]))+" Bytes"+" "+"Src MAC:"+str(pkt.src)+" "+ "DST-MAC:"+str(pkt.dst)+" "+"SRC-PORT:"+str(pkt.sport)+" "+"DST-PORT:"+str(pkt.dport)+""+"SRC-IP:"+str(pkt[IP].src )+" "+"DST-IP:"+str(pkt[IP].dst )+"\n\n")
    if pkt.haslayer(UDP):
        print("UDP", pkt[IP].dst, pkt[IP].src, socket.gethostbyname(socket.gethostname()))
        print(str("[")+str(time)+str("]")+" "+"UDP-IN:{}".format(len(pkt[UDP]))+" Bytes"+" "+"Src MAC:"+str(pkt.src)+" "+ "DST-MAC:"+str(pkt.dst)+" "+"SRC-PORT:"+str(pkt.sport)+" "+"DST-PORT:"+str(pkt.dport)+""+"SRC-IP:"+str(pkt[IP].src )+" "+"DST-IP:"+str(pkt[IP].dst )+"\n\n")
        # if pkt dst ip addr == this machine's ip addr -> incoming
        if socket.gethostbyname(socket.gethostname())==pkt[IP].dst:
            print(str("[")+str(time)+str("]")+" "+"TCP-IN:{}".format(len(pkt[UDP]))+" Bytes"+" "+"Src MAC:"+str(pkt.src)+" "+ "DST-MAC:"+str(pkt.dst)+" "+"SRC-PORT:"+str(pkt.sport)+" "+"DST-PORT:"+str(pkt.dport)+""+"SRC-IP:"+str(pkt[IP].src )+" "+"DST-IP:"+str(pkt[IP].dst )+"\n\n")
        # if pkt src ip addr == this machine's ip addr -> outgoing
        if socket.gethostbyname(socket.gethostname())==pkt[IP].src:
            print(str("[")+str(time)+str("]")+" "+"TCP-IN:{}".format(len(pkt[UDP]))+" Bytes"+" "+"Src MAC:"+str(pkt.src)+" "+ "DST-MAC:"+str(pkt.dst)+" "+"SRC-PORT:"+str(pkt.sport)+" "+"DST-PORT:"+str(pkt.dport)+""+"SRC-IP:"+str(pkt[IP].src )+" "+"DST-IP:"+str(pkt[IP].dst )+"\n\n")
    if pkt.haslayer(ICMP):
        print("ICMP")
        pkt.show()
        # if pkt dst ip addr == this machine's ip addr -> incoming
        if socket.gethostbyname(socket.gethostname())==pkt[IP].dst:
            print(str("[")+str(time)+str("]")+" "+"ICMP-IN:{}".format(len(pkt[ICMP]))+" Bytes"+" "+"Src MAC:"+str(pkt.src)+" "+ "DST-MAC:"+str(pkt.dst)+" "+"SRC-PORT:"+str(pkt.sport)+" "+"DST-PORT:"+str(pkt.dport)+""+"SRC-IP:"+str(pkt[IP].src )+" "+"DST-IP:"+str(pkt[IP].dst )+"\n\n")
        # if pkt src ip addr == this machine's ip addr -> outgoing
        if socket.gethostbyname(socket.gethostname())==pkt[IP].src:
            print(str("[")+str(time)+str("]")+" "+"ICMP-OUT:{}".format(len(pkt[ICMP]))+" Bytes"+" "+"Src MAC:"+str(pkt.src)+" "+ "DST-MAC:"+str(pkt.dst)+" "+"SRC-PORT:"+str(pkt.sport)+" "+"DST-PORT:"+str(pkt.dport)+""+"SRC-IP:"+str(pkt[IP].src )+" "+"DST-IP:"+str(pkt[IP].dst )+"\n\n")

def main():
    # a = sniff(count=10)
    # a.nsummary()
    # sniff(filter="udp and host 127.0.0.1", prn=packet_sniff)
    sniff(filter="udp" ,prn = packet_sniff)

if __name__ == '__main__':
    main()
