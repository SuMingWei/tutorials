import os
import sys

# Client
# simple_switch_CLI for s15
# set meter to | 1*1000*8 bytes | 5*1000*8 bytes |
os.system("simple_switch_CLI --thrift-port 9104 < cmd.txt")