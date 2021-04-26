import socket
import sys
from time import sleep

address = (sys.argv[1], 9999)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
i = 1
while True:
    s.sendto('hi : %d\n' % i, address)
    i += 1
    sleep(3)

s.close()