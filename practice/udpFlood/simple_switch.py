import os
import sys
import time
import re

# Client
# simple_switch_CLI for s15
# set meter to | 1*1000*8 bytes | 5*1000*8 bytes |
# os.system("simple_switch_CLI --thrift-port 9104 < cmd.txt")

import subprocess
# CLI_PATH = "/usr/local/bin/simple_switch_CLI"
# cli = subprocess.run("/usr/local/bin/simple_switch_CLI --thrift-port 9104")
# subprocess.Popen('simple_switch_CLI --thrift-port 9104', shell=True)

# cli = subprocess.Popen('simple_switch_CLI --thrift-port 9104', shell=True,  stdin=subprocess.PIPE)
# cli.communicate("show_tables")
# cli.communicate("meters_get_rate my_meter 0")
class simple_switch_cli:
    def console(self, stdout=None):
        # if stdout is not None:
        #     return(subprocess.Popen('simple_switch_CLI --thrift-port 9104', shell=True,  stdin=subprocess.PIPE, stdout=subprocess.PIPE))
        # return(Popen(["bconsole"], stdout=PIPE, stderr=PIPE, stdin=PIPE))
        return(subprocess.Popen('simple_switch_CLI --thrift-port 9104', shell=True,  stdin=subprocess.PIPE, stdout=subprocess.PIPE))
        # 
    def show_tables(self):
        run = self.console().communicate("show_tables")
        return(run)
    def get_meter_rate(self, meter_name, meter_id):
        rates = self.console().communicate("meter_get_rates %s %s"%(meter_name, meter_id))
        return(rates)
    def read_counter(self, counter_name, counter_id):
        counter = self.console().communicate("counter_read %s %s"%(counter_name, counter_id))
        return(counter)
    def get_time_elapsed(self):
        time = self.console().communicate("get_time_elapsed")
        return(time)
    def get_time_since_epoch(self):                  
        time = self.console().communicate("get_time_since_epoch")
        return(time)

cli = simple_switch_cli()
# cli.show_tables()
# cli.get_meter_rate("my_meter",0)
last_bytes = 0
last_time_stamp_ms = 0
cur_bytes = 0
cur_time_stamp_ms = 0
# bandwidth = 0
# time_diff = 0
for i in range(20):
    time.sleep(0.25)
    counter_text = cli.read_counter("egressPortCounter", 3)[0]
    counter_text = counter_text.split()
    # ['Obtaining', 'JSON', 'from', 'switch...', 'Done', 'Control', 'utility', 'for', 'runtime', 'P4', 'table', 'manipulation', 'RuntimeCmd:', 'egressPortCounter[3]=', 'BmCounterValue(packets=43,', 'bytes=65016)', 'RuntimeCmd:']
    print(counter_text[13], counter_text[14], counter_text[15])
    # counter_text[13] : 'egressPortCounter[3]='
    # counter_text[14] : 'BmCounterValue(packets=43,'
    # counter_text[15] : 'bytes=65016)'
    
    bytes_string = re.split("[(=)]",counter_text[15])
    # bytes_string = re.search("(.+?)=", counter_text[15]).group(1)
    cur_bytes = int(bytes_string[1])
    print(cur_bytes)
    # ['Obtaining', 'JSON', 'from', 'switch...', 'Done', 'Control', 'utility', 'for', 'runtime', 'P4', 'table', 'manipulation', 'RuntimeCmd:', '4241346046', 'RuntimeCmd:']
    # cur_time_stamp_ms = int(cli.get_time_elapsed()[0].split()[13])
    # print(cur_time_stamp_ms)
    cur_time_stamp_ms = int(time.time()*1000.0)
    print(int(time.time()*1000.0))
    if i == 0:
        last_time_stamp_ms = cur_time_stamp_ms
        last_bytes = cur_bytes
        continue
    time_diff = (cur_time_stamp_ms - last_time_stamp_ms)
    byte_diff = (cur_bytes - last_bytes)
    print("Time Diff : {} (ms)".format(time_diff))
    print("Bytes Diff: {} (bytes)".format(byte_diff))
    bandwidth = (byte_diff*1000/time_diff)
    print("Bandwidth : {} (bytes/sec)".format(bandwidth))
    print("Bandwidth : {} (bits/sec)".format(bandwidth*8))
    last_time_stamp_ms = cur_time_stamp_ms
    last_bytes = cur_bytes
