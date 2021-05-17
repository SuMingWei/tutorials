'''
    Used to draw output.png 
'''
import matplotlib.pyplot as plt

time_t = range(0,20)

temp = []
# with open("NoDefense.txt","r") as f:
#     temp = f.read().splitlines()

# ori = []
# for item in temp:
#     ori.append(float(item))

# with open("QoSDefense.txt","r") as f:
#     temp = f.read().splitlines()

# qos = []
# for item in temp:
#     qos.append(float(item))

with open("attack_traffic_ori.txt","r") as f:
    temp = f.read().splitlines()

aori = []
for item in temp:
    aori.append(float(item))

with open("attack_traffic_qos.txt","r") as f:
    temp = f.read().splitlines()

aqos = []
for item in temp:
    aqos.append(float(item))

# draw
plt.figure(figsize=(12,8),dpi=80,linewidth = 3)
# plt.plot(time_t,ori,color = 'r', linestyle="dashed")
# plt.plot(time_t,qos,color = 'b')
plt.plot(time_t,aori,color = 'r', linestyle="dashed")
plt.plot(time_t,aqos,color = 'b')
plt.legend(labels=["without any defense method","with QoS method"])
plt.title("UDP Flood with QoS & without QoS (Attack Traffic)",fontsize=25)
plt.xlabel("time(sec)\nFlood occur at 5s",fontsize=20)
plt.ylabel("Throughput(Mbits/sec)",fontsize=20)
plt.vlines(x=4 ,ymin=0,ymax=10,color="k",linestyle="dashdot",label="UDP Flooding")
# plt.hlines(y=4 ,xmin=0,xmax=20,color="k",linestyle="dotted",label="Guanranteed Rate")
plt.ylim(0,10.0)
plt.savefig("udpflood_h11.png")
plt.show()