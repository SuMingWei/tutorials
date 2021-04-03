# UDP Flood

## Description



## Environment

If you are not have P4 tutorial Virtual Environment:Please Ref. to [p4lang tutorial repo](https://github.com/p4lang/tutorials) 

* Ubuntu 16.04 TLS (P4lang Exercise)
* Programming Dependencies:
    * P4_16
    * Python
    * Bmv2
    * Mininet

## install & run



**Execute makefile**

```
make run
```
Then, mininet will built the topology defined by [topology.json](/static/topology.json) and install the setting file in [static](/static) directory named by `sXruntime.json`, where `X` represented by `0-17` 


## (`IP`、`MAC`) address distribution

### `Switches`
> `X` means don't care (0~255)



Switch Name   |     IP           |           MAC 
--------------|:----------------:|:------------------------:
s1            |  `10.0.0.X`   |    `08:00:01:00:00:00` 
s2            |  `11.0.X.X`   |    `08:00:02:00:00:00` 
s3            |  `11.3.X.X`   |    `08:00:02:03:00:00` 
s4            |  `11.4.X.X`   |    `08:00:02:04:00:00` 
s5            |  `11.5.X.X`   |    `08:00:02:05:00:00` 
s6            |  `11.3.6.X`   |    `08:00:02:03:06:00` 
s7            |  `11.3.7.X`   |    `08:00:02:03:07:00` 
s8            |  `11.3.8.X`   |    `08:00:02:03:08:00` 
s15           |  `11.3.15.X`  |    `08:00:02:03:15:00` 
s9            |  `11.4.9.X`   |    `08:00:02:04:09:00` 
s10           |  `11.4.10.X`  |    `08:00:02:04:10:00` 
s11           |  `11.4.11.X`  |    `08:00:02:04:11:00` 
s12           |  `11.5.12.X`  |    `08:00:02:05:12:00` 
s13           |  `11.5.13.X`  |    `08:00:02:05:13:00` 
s14           |  `11.5.14.X`  |    `08:00:02:05:14:00` 


### `Hosts`

Host Name(Switch)  |     IP           |            MAC 
-------------------|:----------------:|:------------------------:
h1(s1-)            |  `10.0.0.1`   |    `08:00:01:00:00:01` 
h2(s2-s3-s6-)      |  `11.3.6.1`   |    `08:00:02:03:06:02` 
h3(s2-s3-s7-)      |  `11.3.7.1`   |    `08:00:02:03:07:03` 
h4(s2-s3-s8-)      |  `11.3.8.1`   |    `08:00:02:03:08:04` 
h5(s2-s4-s9-)      |  `11.4.15.1`  |    `08:00:02:04:09:05` 
h6(s2-s4-s10-)     |  `11.4.10.1`  |    `08:00:02:04:10:06` 
h7(s2-s4-s11-)     |  `11.4.11.1`  |    `08:00:02:04:11:07` 
h8(s2-s5-s12-)     |  `11.5.12.1`  |    `08:00:02:05:12:08` 
h9(s2-s5-s13-)     |  `11.5.13.1`  |    `08:00:02:05:13:09` 
h10(s2-s5-s14-)    |  `11.5.14.1`  |    `08:00:02:05:14:10` 
h11(s2-s3-s15-)    |  `11.3.15.1`  |    `08:00:02:03:15:11` 