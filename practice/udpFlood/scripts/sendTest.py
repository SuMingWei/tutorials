#!/usr/bin/env python

from scapy.all import *

def main():
    # Send() is used to send packets at the 3rd protocol layer
    send(IP(dst="1.2.3.4")/ICMP())
    # Sendp() is used to send packets at the 2nd protocol layer
    sendp(Ether()/IP(dst="1.2.3.4",ttl=(1,4)), iface="eth1")

if __name__ == '__main__':
    main()