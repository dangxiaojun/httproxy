## httproxy

Layer 4 http / HTTPS proxy  
supports black and white list

#### USAGE
```shell
iptables -t nat -A PREROUTING -p tcp -m multiport --dports 443 -m mark --mark 0x0 -j REDIRECT --to-ports 10443
iptables -t nat -A PREROUTING -p tcp -m multiport --dports 80 -m mark --mark 0x0 -j REDIRECT --to-ports 10080
httproxy -h 0.0.0.0  -p 10080 -t 10443 -f access.list -w
```
```shell
httproxy -help

  -b	run as blacklist mode
  -f string
    	access control rule file
  -h string
    	bind address (default "0.0.0.0")
  -help
    	help
  -p string
    	bind http port (default "80")
  -t string
    	bind https port (default "443")
  -w	run as whitelist mode
```