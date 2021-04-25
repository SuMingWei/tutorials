# UDP Flood

## Description

透過P4程式使Switch能在處理封包時具有一些邏輯，以作為偵測與減緩UDP Flood的方式。
## Environment

If you are not have P4 tutorial Virtual Environment:Please Ref. to [p4lang tutorial repo](https://github.com/p4lang/tutorials) 

* Ubuntu 16.04 TLS (P4lang Exercise)
* Programming Dependencies:
    - P4_16
    - Python
    - Bmv2
    - Mininet

## install & run



**Execute makefile**

```
make run
```
Then, mininet will built the topology defined by [topology.json](/static/topology.json) and install the setting file in [static](/static) directory named by `sXruntime.json`, where `X` represented by `0-17` 


## (`IP`、`MAC`) address Configuration

According to [Classful Network](https://en.wikipedia.org/wiki/Classful_network), we split ip address into the configuration following

* **A Class**：s2
* **B Class**：s3~s5
* **C Class**：s1, s6~s15

### `Switches`
> `X` means don't care (0~255)

Switch Name   |     IP          |           MAC 
--------------|:---------------:|:------------------------:
s1            |  `10.0.0.X`     |    `08:00:01:00:00:00` 
s2            |  `11.X.X.X`     |    `08:00:02:00:00:00` 
s3            |  `11.3.X.X`     |    `08:00:02:03:00:00` 
s4            |  `11.4.X.X`     |    `08:00:02:04:00:00` 
s5            |  `11.5.X.X`     |    `08:00:02:05:00:00` 
s6            |  `11.3.6.X`     |    `08:00:02:03:06:00` 
s7            |  `11.3.7.X`     |    `08:00:02:03:07:00` 
s8            |  `11.3.8.X`     |    `08:00:02:03:08:00` 
s15           |  `11.3.15.X`    |    `08:00:02:03:15:00` 
s9            |  `11.4.9.X`     |    `08:00:02:04:09:00` 
s10           |  `11.4.10.X`    |    `08:00:02:04:10:00` 
s11           |  `11.4.11.X`    |    `08:00:02:04:11:00` 
s12           |  `11.5.12.X`    |    `08:00:02:05:12:00` 
s13           |  `11.5.13.X`    |    `08:00:02:05:13:00` 
s14           |  `11.5.14.X`    |    `08:00:02:05:14:00` 
s16(R1)       |  `10.X.X.X`     |    `08:01:00:00:00:00` 
s17(R2)       |  `11.X.X.X`     |    `08:02:00:00:00:00` 

### `Hosts`

* `IP` Configuration Rule:
```
<Router>.<Switch>.<Switch>.<1>
```
* `MAC` Configuration Rule:
```
<08>.<00>.<Router>.<Switch>.<Switch>.<1>
```

Host Name(Switch)  |     IP           |            MAC 
-------------------|:----------------:|:------------------------:
h1(s1-)            |  `10.0.0.1`      |    `08:00:01:00:00:01` 
h2(s2-s3-s6-)      |  `11.3.6.1`      |    `08:00:02:03:06:01` 
h3(s2-s3-s7-)      |  `11.3.7.1`      |    `08:00:02:03:07:01` 
h4(s2-s3-s8-)      |  `11.3.8.1`      |    `08:00:02:03:08:01` 
h5(s2-s4-s9-)      |  `11.4.9.1`      |    `08:00:02:04:09:01` 
h6(s2-s4-s10-)     |  `11.4.10.1`     |    `08:00:02:04:10:01` 
h7(s2-s4-s11-)     |  `11.4.11.1`     |    `08:00:02:04:11:01` 
h8(s2-s5-s12-)     |  `11.5.12.1`     |    `08:00:02:05:12:01` 
h9(s2-s5-s13-)     |  `11.5.13.1`     |    `08:00:02:05:13:01` 
h10(s2-s5-s14-)    |  `11.5.14.1`     |    `08:00:02:05:14:01` 
h11(s2-s3-s15-)    |  `11.3.15.1`     |    `08:00:02:03:15:01` 

## Experience Assumption

1. 假設UDP Flood的攻擊是來自網路拓樸中Server所允許的ip address，意即駭客會使用同一個subnet底下的Benign IP address，因此防火牆無法辨別哪些白名單內的IP address是已經被駭客控制的。
2. 假設Server(h1)與Benign之間的Bandwidth是固定在某個range的，且一開始的傳輸量不大。

## Attack Scenario

攻擊者(h11)透過將封包的IP address偽造成同一個subnet的Benign IP address以產生大量無法被傳統防火牆阻擋的流量。
## Future work

