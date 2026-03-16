# User Guide

With the framework in this repo, users can model web protocols in the [WIM](https://www.sec.uni-stuttgart.de/research/wim/) and prove security properties using [Tamarin](https://tamarin-prover.com/).

We recommend users to obtain some familiarity with the WIM and running Tamarin before delving into the [guided example](example.md). Below, we document the most important facts your Tamarin rules will likely interact with and other things of note, like the differences to the WIM.

## Facts

### Server
To specify a server handling requests and sending responses, use the facts `!ClaimDomain`, `Receive_Request` and `Send_Reply`. Keep server secrets in the `!ServerSecret` corresponding to the server's domain. Add action facts for source lemmas where needed. Your rules will very likely look like this:

```
[!ClaimDomain($Domain, 'MyServer'),
Receive_Request($Browser, $Domain, ...)]
--[PDAdd...]->
[!ServerSecret,
Send_Reply($Domain, $Browser, ...)]
```

Below, find each of these facts documented:

`!ClaimDomain`: Used to ensure different addresses for different processes. Looks as follows:
`!ClaimDomain($Domain, $Server)`

| Term name | Meaning | Notes |
|---|---|---|
| $Domain | Domain address that has been claimed | usually, this is left as a variable |
| $Server | The name of the server/application that the domain is reserved for | This should be a string constant with the name of your server/application, e.g. 'LoginServer' |

`Receive_Request`: Fact specifying an incoming request. Looks as follows:
`Receive_Request($Browser, $Domain,$Scheme, ~nonce, $method, $path, parameters, cookies, origin, referrer, auth, body)`
| Term name | Meaning | Notes |
|---|---|---|
| $Browser | ID of the browser connecting to you ||
| $Domain | Domain that is being connected to | This should be matched against to handle only requests to your server, i.e. the same variable as in a `!ClaimDomain` fact in the same rule |
| $Scheme | If the request is HTTP or HTTPS | Should only ever have the value 'http' or 'https' |
| ~nonce | The nonce matching request and response | Should be the same in the response |
| $method | The request method (GET, POST, ...) | Names are capitalised (e.g. 'GET')|
| $path | The path which is requested | E.g. '/login', '/access', etc. |
| parameters | The set of parameters | A multiset, so you can match against single parameters using `++`. For example, `params ++ <'Credentials', ~login>` |
| cookies | The set of cookies | A multiset just like the parameters |
| origin | The origin-URL of the request | This is either NoOrigin(), or <$OriginDomain, $OriginScheme> |
| referrer | The referrer-URL of the request | This is either NoReferrer(), or <$RefererScheme, $RefererDomain, $RefererPath, $RefererParams, 'bot'>|
| auth | The basic HTTP authentication scheme (rfc7617) | This is either NoAuth(), or <username, password>|
| body | The request body ||


`Send_Reply`: Fact specifying a response to a request. Looks as follows:
`Send_Reply($Domain, $Browser,$Scheme, ~nonce, $status, setcookiesplain, setcookiessec, location, sts, refpolicy, body)`
| Term name | Meaning | Notes |
|---|---|---|
| $Domain | Domain from which the server is responding from | This should generally match the Domain in the request|
| $Browser | ID of the browser being responded to | This should generally match the browserID in the request |
| $Scheme | If the response is HTTP or HTTPS | This should generally match the scheme of the request |
| ~nonce | The nonce matching request and response | This should generally match the nonce of the request |
| $status | The status code of the response | For example '200', '303', etc. |
| setcookiesplain | The cookies that should be sent to the browser that DO NOT have the secure attribute set | This MUST be of the form `NoCookies() ++ cookie1 ++ ... ++ cookieN`, where each cookie is of the form `<$name, content>`. If no cookies are to be set, simply use `NoCookies()`|
| setcookiessec | The cookies that should be sent to the browser that DO HAVE the secure attribute set | This MUST be of the form `NoCookies() ++ cookie1 ++ ... ++ cookieN`, where each cookie is of the form `<$name, content>`. If no cookies are to be set, simply use `NoCookies()`|
| location | The location header if the status code indicates a redirect | Should be `NoLocation()` or of the form `<$LocationScheme, $LocationDomain, $LocationPath, LocationParameters, Locationfragment>`|
| sts | The Strict-Transport-Security | Should be 'top' if set, and NoSTS() if not set |
| refpolicy | The referrer-policy header | Should be either `'noreferrer'`, `'origin'` or `NoRefPolicy()` |
| body | The response body | Be sure to adhere to the WIM format - non-XHR requests expect a body of the form `<$script, scriptstate>` |

`!ServerSecret`: Fact keeping (secret) server state. This will be used to leak a server's secrets in case of compromise. Looks as follows:
`!ServerSecret($Domain, secret)`
| Term name | Meaning | Notes |
|---|---|---|
| $Domain | Domain address that has been claimed | Should match the domain in  |
| secret | The server's secret content(s) | This can be of any form you'd like |

### Sources 

In oder to prove any properties, you will need to first prove the source lemmas that are included in `sources.spthy`. To do that, annotate your rules with the corresponding facts whenever you send either a cookie (plain or secure) or parameters in your location header:
- Cookies: `PDAddPlainCookie($Domain, $Browser, cookie)` or `PDAddSecCookie($Domain, $Browser, cookie)` respectively
- Parameters: `PDAddParams(params)`


### Server-example
The following rule responds to a https GET request on the '/init' path. It responds with a '200' response, which includes one secure cookie: A freshly generated sessiontoken. Furthermore, that token is stored inside the server secret storage to be used later.

```
rule miniServerIn:
    let body = <'MyScript', 'bot'> in
    [ !ClaimDomain($Domain, 'miniServer')
    , Receive_Request($Browser, $Domain,'https', ~nonce, 'GET', '/init', parameters, cookies, origin, referer, auth, body)
    , Fr(~token)]
    --[PDAddSecCookies($Domain, $Browser, <'SessionToken', ~token>)]->
    [ Send_Reply($Domain, $Browser,'https', ~nonce, '200', NoCookies(), <'SessionToken',~token> ++ NoCookies(), NoLocation(), NoSTS(), NoRefPolicy(), body)
    , !ServerSecret($Domain, <'Sessiontoken', ~token>) ]
``` 
### Script

For Scripts, use the `Document` fact as well as `Send_Request_Browser`. Of course, you might want to interact with the various storage facts like `LocalStorage` as well. Your rules will likely look similar to this:

```
[Document(..., 'MyScript', oldstate)]
--[PDAdd...]->
[Document(..., 'MyScript', newstate),
Send_Request_Browser(...)]
```
Below, you'll find these facts documented:

`Document`: A fact that keeps the current state of a document, including its script and scriptstate. *Important*: When you use a Document fact in the premise, you'll likely want to also keep this fact in the conclusion of your rule. Looks as follows: `Document(~did, $Browser, $TLW, docURL, referer, refpolicy, 'LoginToSite', $ScriptDomain)`

| Term name | Meaning | Notes |
|---|---|---|
| ~did | ID identifying the document||
| $Browser | ID of the browser that contains the document ||
| $TLW | The Top Level Window which contains this document ||
| docURL | The URL that has been requested when getting this document | Is of the form `docURL = <$DocScheme, $DocDomain, $docpath, params, docfragment>`|
| referer | The value of the referer header associated with this document | Is either `NoReferrer()` or of the form `<$RefScheme, $RefDomain, $Refpath, Refparams, Reffragment>`|
| refpolicy | The referrer policy of this document | Is either `NoRefPol()`, `'noreferrer'` or `'origin'` |
| $script | The script that is contained in the document | You will likely want to use a string constant, e.g. `'LoginScript'` or similar|
| scriptstate | The script state of the document||

`Send_Request_Browser`: A fact that is used to send requests from the browser to the network. Looks as follows: `Send_Request_Browser($Browser, wid_or_did, $type, $scheme, $Domain, $Path, parameters, fragment, $method, auth, origin, referrer, referrerpolicy, body)`

| Term name | Meaning | Notes |
|---|---|---|
| $Browser | ID identifying the browser making the request| Should match the browser ID of the document|
| wid_or_did | Top Level Window which will receive the response / Document which will receive the response|
| $type | Wheter the reqeust is a 'REQ' or 'XHR' | values are 'REQ' or 'XHR'|
| $Scheme | If the request is HTTP or HTTPS | Should only ever have the value 'http' or 'https' |
| $Domain | The target domain of the request | You likely want to match this with the `docURL` of the script's document|
| $Path | The path which is requested| e.g. `'/login'`, `'/access'`, etc. |
| parameters | The parameters of the request| Should be of the form `NoParams() ++ YourParam1 ++ YourParam2` |
| fragment | The URL fragment of the request||
| $method | The request method ('GET', 'POST', ...)||
| Auth | The basic HTTP authentication scheme (rfc7617) | This is either `NoAuth()`, or `<username, password>`|
| Origin | The origin-URL of the request | This is either `NoOrigin()`, or `<$OriginDomain, $OriginScheme>` |
| Referrer | The referrer-URL of the request | This is either `NoReferrer()`, or `<$RefererScheme, $RefererDomain, $RefererPath, RefererParams, Referrerfragment>`, this should match your `docURL`|
| Referrerpolicy | The referrerpolicy that is used for this request | This should match your documents' referrerpolicy |
| body | The body of the request |

### Sources 

In oder to prove any properties, you will need to first prove the source lemmas that are included in `sources.spthy`. To do that, annotate your rules with the corresponding facts whenever you send either new parameters or a new body:
- Parameters: `PDAddParams(params)`
- Body: `PDAddBody(body)`

### Example

The following rule takes a Document that includes the "LoginToSite" script, a !Secrets fact (for preshared information) and clicks a link with them.
```
rule LoginScript:
let docURL = <$Scheme, $DocDomain, path, params, fragment>
    docOrigin = <$DocDomain, $Scheme>
    body = <'Credentials',~login> in
   [ Document(~did, $Browser, $TLW, docURL, referer, refpolicy, 'LoginToSite', 'bot')
   , !Secrets($Browser, $DocDomain, $Scheme, ~login) ]
   --[PDAddBody(body)]->
   [ Send_Request_Browser($Browser, $TLW, 'REQ', $Scheme, $DocDomain, '/loginform', NoParams(), 'bot', 'POST', NoAuth(), docOrigin, NoReferrer(), NoRefPolicy(), body)
   , Document(~did, $Browser, $TLW, docURL, referer, refpolicy, 'LoginToSite', 'Scriptover') ]
```

## Flags
We support 4 different flags to make modelling easier. The full featureset should be used when proving.

| Flag | Feature(s) enabled |
| --- | --- |
| -Dstorage | Local and Sessionstorage |
| -Drefpol | Referrerpolicy adherence |
| -Dredirects | 303 and 307 redirects |
| -DAdvscript | Adversary script commands |

## Differences to WIM

As noted in our thesis, there are some differences between our framework and the original WIM:

- There is no support for dedicatedly inspecting protcol behaviour against **web attackers** or **close-corruptions**, only their more powerful versions of network attackers and full corruptions.
- The only supported cookie attribute is `Secure`. There is currently no support for `HttpOnly` or `Session` attributes.
- Adversary scripts have no direct control over cookies. Instead, these must be set via response. This should not make the adversary less powerful, as cookies can be delievered with the adversary script or at a later point via the same requests & responses the adversary script was received
