URI Signing Plugin
==================

This remap plugin implements the draft URI Signing protocol documented [here](https://tools.ietf.org/html/draft-ietf-cdni-uri-signing-16):

It takes a single argument: the name of a config file that contains key information.

**Nota bene:** Take care in ordering the plugins. In general, this plugin
should be first on the remap line. This is for two reasons. First, if no valid
token is present, it is probably not useful to continue processing the request
in future plugins.  Second, and more importantly, the signature should be
verified _before_ any other plugins modify the request. If another plugin drops
or modifies the query string, the token might be missing entirely by the time
this plugin gets the URI.

Config
------

### Keys

The config file should be a JSON object that maps issuer names to JWK-sets.
Exactly one of these JWK-sets must have an additional member indicating the
renewal key.

    {
      "Kabletown URI Authority": {
        "renewal_kid": "Second Key",
        "keys": [
          {
            "alg": "HS256",
            "kid": "First Key",
            "kty": "oct",
            "k": "Kh_RkUMj-fzbD37qBnDf_3e_RvQ3RP9PaSmVEpE24AM"
          },
          {
            "alg": "HS256",
            "kid": "Second Key",
            "kty": "oct",
            "k": "fZBpDBNbk2GqhwoB_DGBAsBxqQZVix04rIoLJ7p_RlE"
          }
        ]
      }
    }

If there is not precisely one renewal key, the plugin will not load.

Although the `kid` and `alg` parameters are optional in JWKs generally, both
members must be present in keys used for URI signing.

### Auth Directives

It's occasionally useful to allow unsigned access to specific paths. To
that end, the `auth_directives` parameter is supported. It can be used
like this:

    {
      "Kabletown URI Authority": {
        "renewal_kid": "Second Key",
        "auth_directives": [
          { auth: "allow", uri: "uri-regex:.*crossdomain.xml" },
          { auth: "deny",  uri: "uri-regex:https?://[^/]*/public/secret.xml.*" },
          { auth: "allow", uri: "uri-regex:https?://[^/]*/public/.*" },
          { auth: "allow", uri: "uri-regex:.*favicon.ico" }
        ]
        "keys": [
          ⋮
        ]
    }

Each of the `auth_directives` will be evaluated in order for each url
that does not have a valid token. If it matches an allowed path before
it matches a denied one, it will be served anyway. If it matches no
`auth_directives`, it will not be served.

It's worth noting that multiple issuers can provide `auth_directives`.
Each issuer will be processed in order and any issuer can provide access to
a path.

### More Configuration Options

**Strip Token**
When the strip_token parameter is set to true, the plugin removes the 
token from both the url that is sent upstream to the origin and the url that 
is used as the cache key. The strip_token parameter defaults to false and should
be set by only one issuer.
**ID**
The id field takes a string indicating the identification of the entity processing the request.
This is used in aud claim checks to ensure that the receiver is the intended audience of a 
tokenized request. The id parameter can only be set by one issuer.
**Redirect Access Parameters**
The redir_add_exp and redir_add_nbf fields indicate how much time to add to the exp and nbf 
claims when issuing redirect access tokens (described below). These can only be set by one issuer.

Example:

    {
      "Kabletown URI Authority": {
        "renewal_kid": "Second Key",
        "strip_token" : true,
        "id" : "mycdn",
        "redir_add_exp" : 60,
        "redir_add_nbf" : -5,
        "auth_directives": [
          ⋮
        ]
        "keys": [
          ⋮
        ]
    }

Usage
-----

The URI signing plugin will block all requests that do not bear a valid JWT, as
defined by the URI Signing protocol. Clients that do not present a valid JWT
will receive a 403 Forbidden response, instead of receiving content.

Tokens will be found in either of these places:

  - A query parameter named `URISigningPackage`. The value must be the JWT.
  - A path parameter named `URISigningPackage`. The value must be the JWT.
  - A cookie named `URISigningPackage`. The value of the cookie must be the JWT.

### Supported Claims

The following claims are understood:

  - `iss`: Must be present. The issuer is used to locate the key for verification.
  - `sub`: May be present, but is not validated.
  - `exp`: Expired tokens are not valid.
  - `nbf`: Tokens processed before this time are not valid.
  - `aud`: Token aud claim strings must match the configured id to be considered valid.
  - `iat`: May be present, but is not validated.
  - `cdniv`: Must be missing, 1 or -1.
  - `cdniuc`: Validated last, after key verification. **Only `regex` is supported!**
  - `cdniets`: If cdnistt is 1, this must be present and non-zero.
  - `cdnistt`: If present, must be 1 or -1.
  - `cdnistd`: If present, must be 0.
  - `x1rt`: Processed if both cdniv and cdnstt are -1. Tokens are renewed after time indicated by x1rt.
  - `x1rts`: Processed if both cdniv and cdnstt are -1. Redirect renewed token's x1rt time is set to now + x1rts seconds.
  - `x1err`: Processed if cdniv is -1. Redirect access tokens will be redirected to the url indicated by this claim.
  - `x1ctx`: Processed if cdniv is -1. Simply copied and placed into redirect access tokens for context. 

### Unsupported Claims

These claims are not supported. If they are present, the token will not validate:

  - `jti`
  - `cdnicrit`
  - `cdniip`

In addition, the `cdniuc` container of `hash` is 
**not supported**.

### Token Renewal
There are currently two supported token renewal methods

**Cookie Renewal**
If the `cdnistt` claim is set to 1 and the `cdniets` claim is present, the token will be renewed
with cookies. The new token will be returned via a `Set-Cookie` header as a session cookie.

However, instead of setting the expiration to be `cdniets` seconds from the
expiration of the previous cookie, it is set to `cdniets` seconds from the time
it was validated. This is to prevent a crafty client from repeatedly renewing
tokens in quick succession to create a super-token that lasts long into the
future, thereby circumventing the intent of the `exp` claim.

**Redirect Renewal**
This method is only exposed with `cdniv` -1. If the `cdnstt` claim is set to -1 and the `x1rt`
and `x1rts` claims are present, the token will be renewed via a redirect. The new token will
replace the old token in the exact same place it was found in the URL. A 302 will then be 
issued so that the client will repeat the request, but with the newly issued token. 

The new token will always be issued if the token is validated after the time indicated 
by `x1rt` and will be scheduled for another renewal `x1rts` seconds from the time of validation.

### Redirect Access Tokens
Both redirect renewals and redirect access tokens are described in the schema outlined [here](https://github.comcast.com/contentsecurity/spec/blob/master/drm-licensing/ZeroSecondDrm.md#redirect-access-token).
If both the `x1err` and `x1ctx` claims are present, redirect access tokens will be issued either
upon failure of validation or if the response from the origin is a 410. The 302 redirect will 
be issued directing the client back to the url specified by the `x1err` claim with the new
redirect token appended. The new redirect token will have the following claims set:
  - `iss`: The name of the signing issuer from the configuration
  - `iat`: The time the redirect token was issued
  - `jti`: A generated uuid
  - `nbf`: Now + add_nbf seconds
  - `exp`: Now + add_exp seconds
  - `x1ctx`: The same x1ctx string from the uri signing token
  - `x1uri`: The URL that was received in the request with any tokens stripped
  - `x1ec`: An Error code indicating why the token was rejected - error codes outlined [here](https://tools.ietf.org/html/draft-ietf-cdni-uri-signing-17#section-4.5)

### JOSE Header

The JOSE header of the JWT should contain a `kid` parameter. This is used to
quickly select the key that was used to sign the token. If it is provided, only
the key with a matching `kid` will be used for validation. Otherwise, all
possible keys for that issuer must be tried, which is considerably more
expensive.

Building
--------

To build from source, you will need these libraries installed:

  - [cjose](https://github.com/cisco/cjose)
  - [jansson](https://github.com/akheron/jansson)
  - pcre
  - OpenSSL

… as well as compiler toolchain.

This builds in-tree with the rest of the ATS plugins. Of special note, however,
are the first two libraries: cjose and jansson. These libraries are not
currently used anywhere else, so they may not be installed.

Note that the default prefix value for cjose is /usr/local. Ensure this is visible to
any executables that are being run using this library.

As of this writing, both libraries install a dynamic library and a static
archive. However, by default, the static archive is not compiled with Position
Independent Code. The build script will detect this and build a dynamic
dependency on these libraries, so they will have to be distributed with the
plugin.

If you would like to statically link them, you will need to ensure that they are
compiled with the `-fPIC` flag in their CFLAGs. If the archives have PIC, the
build scripts will automatically statically link them.
