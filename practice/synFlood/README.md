# SYN Flooding

###### tags: `p4` `SDN` `DDOS`

## 網路拓墣
![](https://i.imgur.com/ngPuvMx.png)

* ### 連線設定：
    * `h1`作為`server`所以可以到達其他`host`；而`host h2~h11`只能與`server`連線不可到達其他`host`。
    ![](https://i.imgur.com/pxN2oik.png)
    * **不同網域的連線需要透過`gateway`，在`topology.json`有新增預設的`gw`。**
    * **當兩個`host`因為子網域不同而需要通過`gateway`連線時，其`dst_addr` 會被設為`gateway`的`MAC address`。**
