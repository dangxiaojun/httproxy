## httproxy

4层HTTP,HTTPS代理

#### USAGE

```shell
ip l s tcpproxy  >/dev/null 2>&1 ||  ip tuntap add dev tcpproxy mode tun user root;ifconfig tcpproxy 172.31.255.254/24 up
iptables -t nat -A PREROUTING -p tcp -m multiport --dports 80,443 -m mark --mark 0x0 -j DNAT --to-destination 172.31.255.254:88
iptables -t nat -A OUTPUT -p tcp -m multiport --dports 80,443 -m mark --mark 0x0 -j DNAT --to-destination 172.31.255.254:88
./httproxy -f access.list
```
