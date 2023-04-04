# Web Cache Deception Attack
* [Param Miner - PortSwigger](https://github.com/PortSwigger/param-miner)
    > This extension identifies hidden, unlinked parameters. 
    > It's particularly useful for finding web cache poisoning vulnerabilities.
# Exploit
<>
1. Browser requests `http://www.example.com/home.php/non-existent.css`.
2. Server returns content of `http://www.example.com/home.php`, with HTTP caching headers that instruct to not cache this page.
3. The response goes through Burp-Suite.
4. The proxy identifies .css extension.
5. Under cache directory, proxy creates a directory named home.php, and caches imposter "CSS" file (non-existent.css) inside.
<>
# Methodology of attack 
1. Normal browsing, visit home : `https://www.example.com/myaccount/home/`
2. Open malicious link : `https://www.example.com/myaccount/home/malicious.css`
3. Page is displayed as /home and cache is saving the page
4. Open a private tab with the previous URL : `https://www.paypal.com/myaccount/home/malicous.css`
5. The Apache is displayed
<>
Video of attack by Omer Gil - Web Cache Deception Attack in PayPal Home Page
[![DEMO](https://i.vimeocdn.com/video/674856618.jpg)](https://vimeo.com/249130093)
# Methodology 2
<>
1. Find an unkeyed input for a Cache Poisoning
    Values: User-Agent
    Values: Cookie
    Header: X-Forwarded-Host
    Header: X-Host
    Header: X-Forwarded-Server
    Header: X-Forwarded-Scheme (header; also in combination with X-Forwarded-Host)
    Header: X-Original-URL (Symfony)
    Header: X-Rewrite-URL (Symfony)
2. Cache poisoning attack - Example for `X-Forwarded-Host` unkeyed input (Remember to use Buster to only cache this webpage instead of main page of website.)
    GET /test?buster=123 HTTP/1.1
    Host: target.com
    X-Forwarded-Host: test"><script>alert(1)</script>
<>
    HTTP/1.1 200 OK
    Cache-Control: public, no-cache
    [..]
    <meta property="og:image" content="https://test"><script>alert(1)</script>">
# References
* [Web Cache Deception Attack - Omer Gil](http://omergil.blogspot.fr/2017/02/web-cache-deception-attack.html)
* [Practical Web Cache Poisoning - James Kettle @albinowax](https://portswigger.net/blog/practical-web-cache-poisoning)
* [Web Cache Entanglement: Novel Pathways to Poisoning - James Kettle @albinowax](https://portswigger.net/research/web-cache-entanglement)
* [Web Cache Deception Attack leads to user info disclosure - Kunal pandey - Feb 25](https://medium.com/@kunal94/web-cache-deception-attack-leads-to-user-info-disclosure-805318f7bb29)
* [Web cache poisoning - Web Security Academy learning materials](https://portswigger.net/web-security/web-cache-poisoning)
  - [Exploiting cache design flaws](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws)
  - [Exploiting cache implementation flaws](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws)
