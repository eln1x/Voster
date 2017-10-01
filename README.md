
![VOSTER](https://raw.githubusercontent.com/eln1x/Voster/master/images/banner.png)

## What is voster
Voster is Python program design to workaround FQDN trying to get the real IP by brute-force targeted subnets.

in essence, voster exploit the weak security implementation for public exposed nodes that should accept only traffic from Load Balancer or the reverse proxy.

#### Matching techniques
- Fingerprint matching feed voster with unique string like a class name or other and let it lookup for you
- Collecting destination from `Location` Header 
- Considering Reverse-Proxy webserver's and collecting `X-Cache` header 

### Extra
- External DNS lookup API to collect MX and *NS* records and scan it subnet
- Multi-Threaded with nice Colors
- support both of HTTP/HTTPS Protocols 

## Arguments
  |short|long|description|
  |---|---|---|
  |-h|--help        |show this help message and exit|
  |-d|--domain      |target domain name|
  |-p|--port        |target port number|
  |-m|--method      |target domain name|
  |-t|--threads     |number of threads|
  |-s|--subnet      |range to scan example: 192.168.1.1/24|
  |-f|--fingerprint |a unique string exist inside the web contenet example: CyberSpace_logo150x150.png|
  |-x|--timeout     |connection timeout for the http request|
 
## Examples
- scanning a subnet you know for vhosts with a specific keyword with 20 thread and matching keyword **powered by dev-x**
```
python voster.py --domain secret-domain.com --subnet 192.168.72.136/24 --threads 20 --fingerprint="powered by dev-x"
```
- scanning a subnet for adomain without fingerprint to get review what websites are running , voster will display server banner , title , response status , length , redirect url,
```
python voster.py --domain google.com --subnet 192.168.72.136/24 
```
- scanning a adomain with a fingerprint text using the DNS API to collect subnets for you
```
python voster.py --domain google.com --fingerprint="accounts.google.com/ServiceLogin"
```
![dns api](https://raw.githubusercontent.com/eln1x/Voster/master/images/collect-dns.png)



####

## How it works
Voster idea to automate **crafted** `HOST` headers against subnets trying to detect if the target IP react to the host header,
here is the example: IP XX.XX.XX.XX hosts a website in a virtual host if you try to visit the website it will show the default webroot for the web server, not the site you are looking for but if you send a request to the IP but the Host header value is the target domain? 
yes the crafted request will load the site secret-domain.com content.
this is same techinique when you staticly link a dns in your */etc/hosts* file but we do it in brute-force by voster 

## Why
- once upon a time you found web-exploit and you wrote the POC but you love red teaming  
- you got ruined by a cloud waf  



## Installation
```
git clone git@github.com:eln1x/Voster.git
```

## Compatibility
Voster tested on `Python 2.7` under Linux/MacOS 

## Dependencies:
Voster depends on [`argparse`,`bs4`,`requests`,`ipaddr`]

- Linux setup 
```
pip install -r requirements.txt
````
