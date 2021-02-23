## httproxy

Layer 4 http / HTTPS proxy  
supports black and white list

#### USAGE
```shell
httproxy -h 0.0.0.0  -p 80 -t 443 -f access.list -w
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