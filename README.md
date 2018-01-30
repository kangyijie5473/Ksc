### Ksc  
KangKang 's Simple Capturer  
一个Linux平台下基于libpcap的抓包工具，适用于在Linux平台上的网络编程初学者。  
只捕捉了应用层数据，便于在网络编程学习中查看数据收发正确性。

### 快速开始

编译
```
$ git clone git@github.com:kangyijie5473/Ksc.git
$ cd Ksc
$ sudo su
# make
```

用法
```
# ./ksc -d device_name -n packet_nums -i ip_address -o src -p port -O dst

```
比如需要查看 lo上的来自127.0.0.1 的80端口的包
```
# ./ksc -d lo -i 127.0.0.1 -o src -p 80 -O src
```
