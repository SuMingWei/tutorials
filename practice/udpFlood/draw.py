'''
    Used to draw output.png 
'''
import matplotlib.pyplot as plt

time_t = range(0,20)

temp = []
with open("out/NoDefense.txt","r") as f:
    temp = f.read().splitlines()

ori = []
for item in temp:
    ori.append(float(item))

with open("out/QoSDefense.txt","r") as f:
    temp = f.read().splitlines()

qos = []
for item in temp:
    qos.append(float(item))

# with open("out/attack_traffic_ori.txt","r") as f:
#     temp = f.read().splitlines()

# aori = []
# for item in temp:
#     aori.append(float(item))

# with open("out/attack_traffic_qos.txt","r") as f:
#     temp = f.read().splitlines()

# aqos = []
# for item in temp:
#     aqos.append(float(item))
plt.rcParams.update({'font.size': 15})
plt.rcParams['pdf.fonttype'] = 42
plt.rcParams['ps.fonttype'] = 42
# draw
plt.figure(figsize=(12,8),dpi=80,linewidth = 3)
plt.plot(time_t,ori,color = 'r', linestyle="dashdot")
plt.plot(time_t,qos,color = 'b')
# plt.plot(time_t,aori,color = 'r', linestyle="dashdot")
# plt.plot(time_t,aqos,color = 'b')
plt.legend(labels=["w/o meter","w/   meter"], fontsize=30)
# plt.title("Traffic server received, with & without meter (Malicious)",fontsize=24)
plt.xlabel("Time (sec)",fontsize=34)
plt.ylabel("Throughput (Mbits/sec)",fontsize=34)
plt.vlines(x=4 ,ymin=0,ymax=10,color="k",linestyle="dashed",label="UDP Flooding")
plt.xticks(fontsize=25)
plt.yticks(fontsize=25)
# plt.hlines(y=4 ,xmin=0,xmax=20,color="k",linestyle="dotted",label="Guanranteed Rate")
plt.ylim(0.0,10.0)
plt.savefig("test.eps", format='eps')
plt.show()