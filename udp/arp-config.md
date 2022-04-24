
We need to add an ARP record in local machine since local machine and ubuntu server are in different network.

> arp -s 192.168.71.67 00:0c:29:7e:8f:5d

# ubuntu server
```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
    inet 192.168.71.67  netmask 255.255.240.0  broadcast 192.168.79.255
    inet6 fe80::9fc7:409:d5ac:f264  prefixlen 64  scopeid 0x20<link>
    ether 00:0c:29:7e:8f:5d  txqueuelen 1000  (Ethernet)
    RX packets 190  bytes 42629 (42.6 KB)
    RX errors 0  dropped 0  overruns 0  frame 0
    TX packets 140  bytes 15732 (15.7 KB)
    TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```


# local machine

```
jiewang3@JIEWANG3-M-V0R2 dpdk % arp -a
? (172.16.70.1) at 8a:66:5a:35:73:65 on bridge101 ifscope permanent [bridge]
? (172.16.70.134) at 0:c:29:7e:8f:67 on bridge101 ifscope [bridge]
? (192.168.64.254) at 80:5:88:77:9b:65 on en0 ifscope [ethernet]
? (192.168.67.203) at 18:56:80:5:48:df on en0 ifscope [ethernet]
? (192.168.67.242) at b2:a2:79:d8:3b:b4 on en0 ifscope [ethernet]
? (192.168.70.61) at 94:bf:2d:c:9f:95 on en0 ifscope [ethernet]
? (192.168.70.175) at ee:1c:ee:40:d6:3e on en0 ifscope [ethernet]
? (192.168.70.207) at 94:58:cb:34:a0:87 on en0 ifscope [ethernet]
? (192.168.70.208) at de:f7:97:5a:96:94 on en0 ifscope [ethernet]
? (192.168.70.220) at da:c4:e7:8:8c:f5 on en0 ifscope [ethernet]
? (192.168.70.232) at 8c:7a:aa:e8:12:62 on en0 ifscope [ethernet]
? (192.168.71.25) at ee:55:60:a1:e7:be on en0 ifscope [ethernet]
? (192.168.71.57) at 42:11:32:71:7:58 on en0 ifscope [ethernet]
? (192.168.71.74) at b2:c3:8:23:3e:d9 on en0 ifscope [ethernet]
? (192.168.77.151) at cc:2f:71:26:2a:37 on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on bridge101 ifscope permanent [ethernet]
```