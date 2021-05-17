# coding=utf-8
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
    def __init__(self, port=None):
        self.port = port if port is not None else 9104
    def console(self, stdout=None):
        # if stdout is not None:
        #     return(subprocess.Popen('simple_switch_CLI --thrift-port 9104', shell=True,  stdin=subprocess.PIPE, stdout=subprocess.PIPE))
        # return(Popen(["bconsole"], stdout=PIPE, stderr=PIPE, stdin=PIPE))
        return(subprocess.Popen('simple_switch_CLI --thrift-port {}'.format(self.port), shell=True,  stdin=subprocess.PIPE, stdout=subprocess.PIPE))
        # 
    def show_tables(self):
        run = self.console().communicate("show_tables")
        return(run)
    def get_meter_rate(self, meter_name, meter_id):
        rates = self.console().communicate("meter_get_rates %s %s"%(meter_name, meter_id))[0]
        return(rates)
    def read_counter(self, counter_name, counter_id):
        counter = self.console().communicate("counter_read %s %s"%(counter_name, counter_id))[0]
        return(counter)
    def get_time_elapsed(self):
        time = self.console().communicate("get_time_elapsed")[0]
        return(time)
    def get_time_since_epoch(self):                  
        time = self.console().communicate("get_time_since_epoch")
        return(time)
    def set_meter_rate(self, meter_name, meter_id, cir_burst, pir_burst):
        rates = self.console().communicate("meter_set_rates %s %s %s %s"%(meter_name, meter_id, cir_burst, pir_burst))
        return(rates)
    def get_register_value(self, register_name, register_index):
        reg = self.console().communicate("register_read %s %s"%(register_name, register_index))[0]
        return(reg)
'''
    Monitor for data
'''
cli = []
cli.append(simple_switch_cli(0))
for i in range(15):
    cli.append(simple_switch_cli(i+9090))
# 設定Server-side的Detection用Meter
print("[+] Setting Meter Server Bandwidth...")
cli_3 = cli[3]
# 設為0.000005時是 40 kbits/sec, 200*0.000005時為最高 8 Mbits/sec
# | green -4M+ yellow -8M+ red |
Server_Bandwidth = 200
# Server_Max_Egress_Port = 20
# for i in range(Server_Max_Egress_Port+1):
#     cli[3].set_meter_rate("my_meter", i, "{}:1".format(0.0000025*Server_Bandwidth), "{}:1".format(0.000005*Server_Bandwidth))
print("[+] Start Monitor on s1 for h2...")
cli = simple_switch_cli(9090)
MONITOR_PORT = 2
out_data = []
cur_byte = 0
last_byte = 0
last_time_stamp_ms = 0
cur_time_stamp_ms = 0
time_diff = 0
byte_diff = 0
for i in range(0,5):
    print("======== {} START ===========".format(i))
    cur_time_stamp_ms = int(time.time()*1000.0)
    counter_text = cli.read_counter("MonitorCounter", 0).split()
    bytes_string = re.split("[(=)]",counter_text[15])
    cur_byte = int(bytes_string[1])
    if i == 0:
        time_diff = cur_time_stamp_ms
        byte_diff = cur_byte
    else:
        time_diff = (cur_time_stamp_ms - last_time_stamp_ms)
        byte_diff = cur_byte - last_byte
    bandwidth = byte_diff/time_diff
    print(byte_diff, time_diff, bandwidth)
    print("Bandwidth : {} (bits/sec)".format(bandwidth*8))
    last_time_stamp_ms = cur_time_stamp_ms
    last_byte = cur_byte
    out_data.append((bandwidth*8.0)/1024.0)
    time.sleep(1)
    print("==========  END  ===========")
print(len(out_data))
tmp = raw_input()
cli_3.set_meter_rate("my_meter", 15, "{}:1".format(0.000001*Server_Bandwidth), "{}:1".format(0.0000025*Server_Bandwidth))
cli_3.set_meter_rate("my_meter", 6, "{}:1".format(0.000001*Server_Bandwidth), "{}:1".format(0.0000025*Server_Bandwidth))
# after attack do again
for i in range(1,17):
    print("========== START ===========")
    cur_time_stamp_ms = int(time.time()*1000.0)
    counter_text = cli.read_counter("MonitorCounter", 0).split()
    bytes_string = re.split("[(=)]",counter_text[15])
    cur_byte = int(bytes_string[1])
    time_diff = (cur_time_stamp_ms - last_time_stamp_ms)
    byte_diff = cur_byte - last_byte
    bandwidth = byte_diff/time_diff
    print(byte_diff, time_diff, bandwidth)
    print("Bandwidth : {} (bits/sec)".format(bandwidth*8))
    if i == 1:
        last_time_stamp_ms = cur_time_stamp_ms
        last_byte = cur_byte
        time.sleep(1)
        continue
    last_time_stamp_ms = cur_time_stamp_ms
    last_byte = cur_byte
    out_data.append((bandwidth*8.0)/1024.0)
    time.sleep(1)
    print("==========  END  ===========")
print(out_data)
f = open("test.txt", "w")
for i in out_data:
    f.write("%f\n" % (i))
f.close()
exit(1)
# # For test
# cli = []
# cli.append(simple_switch_cli(0))
# for i in range(15):
#     cli.append(simple_switch_cli(i+9090))
# # 設定Server-side的Detection用Meter
# print("[+] Setting Meter Server Bandwidth...")
# # 設為0.000005時是 40 kbits/sec, 200*0.000005時為最高 8 Mbits/sec
# # | green -4M+ yellow -8M+ red |
# Server_Bandwidth = 200
# Server_Max_Egress_Port = 20
# for i in range(Server_Max_Egress_Port+1):
#     cli[3].set_meter_rate("my_meter", i, "{}:1".format(0.0000025*Server_Bandwidth), "{}:1".format(0.000005*Server_Bandwidth))
# cli = simple_switch_cli(9092)
# MAX_PORT = 20
# while True:
#     # 獲得s3 egress時能用的Bandwidth與meter設定
#     print("========== START ===========")
#     start = time.time()

#     rates = []
#     CIRS = []
#     PIRS = []
#     CIR_BURSTS = []
#     PIR_BURSTS = []
#     regs = []
#     cur_bytes = [0]*(MAX_PORT+1)
#     for i in range(MAX_PORT+1):
#         rates = cli.get_meter_rate("my_meter", i).split()
#         CIR = float(rates[17][0:-1])*1000*8
#         CIR_BURST = int(rates[21])
#         PIR = float(rates[26][0:-1])*1000*8
#         PIR_BURST = int(rates[30])
#         CIRS.append(CIR)
#         CIR_BURSTS.append(CIR_BURST)
#         PIRS.append(PIR)
#         PIR_BURSTS.append(PIR_BURST)
#         reg = cli.get_register_value("reg", i).split()
#         value = int(reg[14])
#         regs.append(value)
#         # 獲得ingress_port的counter值
#         counter_text = cli.read_counter("ingressPortCounter", i)
#         counter_text = counter_text.split()

#         bytes_string = re.split("[(=)]",counter_text[15])
#         cur_bytes[i] = int(bytes_string[1])
#     print(CIRS)
#     print(PIRS)
#     # print(CIR_BURSTS)
#     # print(PIR_BURSTS)
#     print(cur_bytes)
#     print(regs)
#     end = time.time()
#     print("執行時間：%f 秒" % (end - start))
#     print("==========  END  ===========")
#     # time.sleep(1)
# ================================================ #
# 建立 CLI list 和 TimeStamp list
cli = []
timeStamp = []
cli.append(simple_switch_cli(0))
timeStamp.append(int(time.time()*1000.0))
for i in range(15):
    cli.append(simple_switch_cli(i+9090))
    timeStamp.append(int(time.time()*1000.0))
# cli = simple_switch_cli(9104)
# ================================================ #
# 設定Server-side的Detection用Meter
print("[+] Setting Meter Server Bandwidth...")
# 設為0.000005時是 40 kbits/sec, 200*0.000005時為最高 8 Mbits/sec
# | green -4M+ yellow -8M+ red |
Server_Bandwidth = 200
Server_Max_Egress_Port = 20
for i in range(Server_Max_Egress_Port+1):
    cli[1].set_meter_rate("dstPortMeter", i, "{}:1".format(0.0000025*Server_Bandwidth), "{}:1".format(0.000005*Server_Bandwidth))
# ================================================ #
# # Detection on s1
# Predefined_Threshold = 6000
# last_value = int(cli[1].get_register_value("suspectedTraffic", 1).split()[14])
# while True:
#     # Assume Server is at port 1, so just monitor port 1
#     time.sleep(0.1)
#     reg = cli[1].get_register_value("suspectedTraffic", 1).split()
#     # ['Obtaining', 'JSON', 'from', 'switch...', 'Done', 'Control', 'utility', 'for', 'runtime', 'P4', 'table', 'manipulation', 'RuntimeCmd:', 'suspectedTraffic[1]=', '28380', 'RuntimeCmd:']
#     value = int(reg[14])
#     delta = value - last_value
#     last_value = value
#     print(delta)
#     # print(value)
#     if delta > Predefined_Threshold:
#         print(value, delta, "This is a alert") 
# ================================================ #
# 設定初始Bandwidth on s3
print("[+] Initailize s3's Meter rate...\n")
MAX_PORT = 20
for i in range(MAX_PORT+1):
    cli[3].set_meter_rate("my_meter", i, "{}:1".format(0.0000025*Server_Bandwidth), "{}:1".format(0.000005*Server_Bandwidth))
# ================================================ #
# 透過設定的egress Bandwidth和P4runtime讀取的ingress Bandwidth動態調整s3的ingress Bandwidth
last_bytes = [0]*(MAX_PORT+1)
last_time_stamp_ms = [0]*(MAX_PORT+1)
cur_bytes = [0]*(MAX_PORT+1)
cur_time_stamp_ms = [0]*(MAX_PORT+1)
while True:
    # 建立一個 list 儲存 switch的ingress bandwidth資訊
    sw = [0]*(MAX_PORT+1)
    # 獲得s3 egress時能用的Bandwidth與meter設定
    rates = cli[3].get_meter_rate("my_meter", 2).split()
    # ['Obtaining', 'JSON', 'from', 'switch...', 'Done', 'Control', 'utility', 'for', 'runtime', 'P4', 'table', 'manipulation', 'RuntimeCmd:', '0:', 'info', 'rate', '=', '1e-06,', 'burst', 'size', '=', '1', '1:', 'info', 'rate', '=', '5e-06,', 'burst', 'size', '=', '1', 'RuntimeCmd:']
    # rates[17] : 1e-06,
    # rates[21] : 1
    # rates[26] : 5e-06,
    # rates[30] : 1
    CIR = float(rates[17][0:-1])*1000*8
    CIR_BURST = int(rates[21])
    PIR = float(rates[26][0:-1])*1000*8
    PIR_BURST = int(rates[30])
    for j in range(MAX_PORT+1):
        # ================================================ #
        # 獲得ingress_port的counter值
        counter_text = cli[3].read_counter("ingressPortCounter", j)
        counter_text = counter_text.split()
        # ['Obtaining', 'JSON', 'from', 'switch...', 'Done', 'Control', 'utility', 'for', 'runtime', 'P4', 'table', 'manipulation', 'RuntimeCmd:', 'ingressPortCounter[3]=', 'BmCounterValue(packets=43,', 'bytes=65016)', 'RuntimeCmd:']
        # counter_text[13] : 'ingressPortCounter[3]='
        # counter_text[14] : 'BmCounterValue(packets=43,'
        # counter_text[15] : 'bytes=65016)'
        bytes_string = re.split("[(=)]",counter_text[15])
        cur_bytes[j] = int(bytes_string[1])
        if cur_bytes[j] == 0:
            last_time_stamp_ms[j] = cur_time_stamp_ms[j]
            last_bytes[j] = cur_bytes[j]
            continue
        # print("Current bytes in Counter : {} at port {}".format(cur_bytes[j], 3))
        # ================================================ #
        # 獲取現在時間以計算時間差
        cur_time_stamp_ms[j] = int(time.time()*1000.0)
        time_diff = (cur_time_stamp_ms[j] - last_time_stamp_ms[j])
        # 計算與上次的counter值之差異
        byte_diff = (cur_bytes[j] - last_bytes[j])
        # 利用差異估算bandwidth
        # 可能會有誤差, 原因 : 計算的時間過久, 導致計算出的bandwidth非當下而是有點delay
        bandwidth = (byte_diff*1000/time_diff) if time_diff is not 0 else time_diff 
        # print("Bandwidth : {} (bytes/sec)".format(bandwidth))
        # print("Bandwidth : {} (bits/sec)".format(bandwidth*8))
        # print("Bandwidth : {} (Kbits/sec)".format((bandwidth*8)/1024))
        last_time_stamp_ms[j] = cur_time_stamp_ms[j]
        last_bytes[j] = cur_bytes[j]
        sw[j] = bandwidth*8
    print("[INFO] Bandwidth on each ports : \n{}".format(sw))
    # 建立一個 list 儲存計算後的ingress分配
    ports_bandwidth = [0]*(MAX_PORT+1)
    for i in range(MAX_PORT+1):
        if sw[i] != 0:
            ports_bandwidth[i] = 1
    # 利用Fair的方式分配
    number_ports_used = sum(ports_bandwidth)
    print("[INFO] Current # of active ingress port : {}".format(number_ports_used))
    if number_ports_used > 0:
        _PIR = (float(PIR*1000.0))/40.0
        for i in range(MAX_PORT+1):
            if ports_bandwidth[i] == 0:
                continue
            print("[INFO] set meter PIR {} on port:{}...".format((1.0/number_ports_used)*_PIR*0.000005, i))
            cli[3].set_meter_rate("my_meter", i, "{}:1".format("1e-06"), "{}:1".format((1.0/number_ports_used)*_PIR*0.000005))
    