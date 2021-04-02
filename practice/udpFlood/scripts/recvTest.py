#!/usr/bin/env python

from scapy.all import sniff, get_if_list

def main():
    a = sniff(count=10)
    a.nsummary()

if __name__ == '__main__':
    main()
