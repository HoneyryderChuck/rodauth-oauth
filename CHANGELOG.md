# CHANGELOG

## master

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