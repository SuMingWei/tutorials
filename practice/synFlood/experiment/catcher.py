import commands
from time import sleep

syn_recv_num = []

for i in range(70):
    x = commands.getoutput("netstat -n | grep SYN_RECV | wc -l")
    #num = commands.getoutput("netstat -n | grep ESTA | wc -l")
    print("time: %s, utilization of syn queue: %s") %(i,str(float(int(x)/5.0)*100))
    #syn_recv_num.append([x,num])
    sleep(1)

# f = open('esta1.txt','w')
# for item in syn_recv_num:
#     #f.write(str(float(int(item)/5.0)))
#     f.write(item[0])
#     f.write(" ")
#     f.write(item[1])
#     f.write("\n")

# f.close()
