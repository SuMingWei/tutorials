import os
from time import sleep

for i in range(10):
    cmd = "nc 10.0.1.1 5001 -p " + str(500+i)
    os.system(cmd)

sleep(3)
# for i in range(10):
#     cmd = "hping3 10.0.1.1 -p 5001 -S -c 1 -s " + str(500+i)
#     os.system(cmd)

for i in range(10):
    cmd = "hping3 10.0.1.1 -p 5001 -S -c 1 -s " + str(500+i)
    os.system(cmd)
    





    


