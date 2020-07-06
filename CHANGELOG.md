# CHANGELOG

## master

### 0.0.6

#### Features

The `oauth_jwt` feature now supports JWT Secured Authorization Request (JAR) (see https://tools.ietf.org/html/draft-ietf-oauth-jwsreq-20). This means that client applications can send the authorization parameters inside a signed JWT. The client applications keeps the private key, while the authorization server **must** store a public key for the client application. For encrypted JWTs, the client application should use one of the public encryption keys exposed in the JWKs URI, to encrypt the JWT. Remember, **tokens must be signed then encrypted** (or just signed).

###### Options:

* `:oauth_application_jws_jwk_column`: db column where the public key is stored; since it's stored in the JWS format, it can be stored either as a String (JSON-encoded), or as an hstore (if you're using postgresql);
* `:oauth_jwt_jwe_key`: key used to decrypt the request JWT;
* `:oauth_jwt_jwe_public_key`: key used to encrypt the request JWT, and which will be exposed in the JWKs URI in the JWK format;


#### Improvements

* Removing all `_param` options; these defined the URL params, however we're using protocol-defined params, so it's unlikely (and undesired) that these'll change.
* Hitting the revoke endpoint with a JWT access token returns a 400 error;

#### Chore

Removed React Javascript from example applications.


### 0.0.5 (26/6/2020)

#### Features

* new option: `oauth_scope_separator` (default: `" "`), to define how scopes are stored;

##### Resource Server mode

`rodauth-oauth` can now be used in a resource server, i.e. only for authorizing access to resources:


```ruby
plugin :rodauth do
  enable :oauth

  is_authorization_server? false
  authorization_server_url "https://auth-server"
end
```

It **requires** the authorization to implement the server metadata endpoint (`/.well-known/oauth-authorization-server`), and if using JWS, the JWKs URI endpoint (unless `oauth_jwt_public_key` is defined).

#### Improvements

* Multiple Redirect URIs are now allowed for client applications out-of-the-box. In order to use it in API mode, you can pass the `redirect_uri` with an array of strings (the URLs) as values; in the new client application form, you can add several input fields with name field as `redirect_uri[]`. **ATTENTION!!** When using multiple redirect URIs, passing the desired redirect URI to the authorize form becomes mandatory.
* store scopes with whitespace instead of comma; set separator as `oauth_scope_separator` option, to keep backwards-compatibility;
* client application can now store multiple redirect uris; the POST API parameters can accept the redirect_uri param value both as a string or an array of string; internally, they'll be stored in a whitespace-separated string;

#### Bugfixes

* Fixed `RETURNING` support in the databases supporting it (such as postgres).

#### Chore

* option `scopes_param` renamed to `scope_param`;
*

## 0.0.4 (13/6/2020)

### Features

#### Token introspection

`rodauth-oauth` now ships with an introspection endpoint (`/oauth-introspect`).

#### Authorization Server Metadata

`rodauth-oauth` now allows to define an authorization metadata endpoint, which has to be defined at the route of the router:

```ruby
route do |r|
  r.rodauth
  rodauth.oauth_server_metadata
  ...
```

#### JWKs URI

the `oauth_jwt` feature now ships with an endpoint, `/oauth-jwks`, where client applications can retrieve the JWK set to verify generated tokens.

#### JWT access tokens as authorization grants

The `oauth_jwt` feature now allows the usage of access tokens to authorize the generation of new tokens, [as per the RFC](https://tools.ietf.org/html/rfc7523#section-4);

### Improvements

* using `client_secret_basic` authorization where client id/secret params were allowed (i.e. in the token and revoke endpoints, for example);
* improved JWK usage for both supported jwt libraries;
* marked `fetch_access_token` as auth_value_method, thereby allowing users to fetch the access token from other sources than the "Authorization" header (i.e. form body, query params, etc...)

### Bugfixes

* Fixed scope claim of JWT ("scopes" -> "scope");

## 0.0.3 (5/6/2020)

### Features

#### `:oauth_http_mac`

A new feature builds on top of `:oauth` to allow MAC authorization.

```ruby
plugin :rodauth do
  enable :oauth_http_mac
  # options here...
end
```

#### `:oauth_jwt`

Another new feature, this time supporting the generation of JWT access tokens.

```ruby
plugin :rodauth do
  enable :oauth_jwt
  # options here...
end
```

### Improvements

* added options for disabling pkce and access type (respectively, `use_oauth_pkce?` and `use_oauth_access_type?`);
* renamed the existing `use_oauth_implicit_grant_type` to `use_oauth_implicit_grant_type?`;
* It's now usable as JSON API (small caveat: POST authorize will still redirect on success...);

## 0.0.2 (29/5/2020)

### Features

* Implementation of PKCE by OAuth Public Clients (https://tools.ietf.org/html/rfc7636);
* Implementation of grants using "access_type" and "approval_prompt" ([similar to what Google OAuth 2.0 API does](https://wiki.scn.sap.com/wiki/display/Security/Access+Google+APIs+using+the+OAuth+2.0+Client+API));

### Improvements

* Store token/refresh token hashes in the database, instead of the "plain" tokens;
* Client secret hashed by default, and provided by the application owner;

### Fix

* usage of client secret for authorizing the generation of tokens, as the spec mandates (and refraining from them when doing PKCE).

## 0.0.1 (14/5/2020)

Initial implementation of the Oauth 2.0 framework, with an example app done using roda.