# CHANGELOG

## master

### 0.4.0

### Features

* A new method, `get_additional_param(account, claim)`, is now exposed; this method will be called whenever non-OIDC scopes are requested in the emission of the ID token.

* The `form_post` response is now supported, either by passing the `response_mode=form_post` request param in the authorization URL, or by setting `oauth_response_mode "form_post"` option. This improves the overall security of an Authorization server even more, as authorization codes are sent to client applications via a POST request to the redirect URI.


### Improvements

* For the OIDC `address` scope, proper claims are now emitted as per the standard, i.e. the "formatted", "street_address", "locality", "region", "postal_code", "country". These will be the ones referenced in the `get_oidc_param` method.

### Bugfixes

* The rails templates were missing declarations from a few params, which made some of the flows (the PKCE for example) not work out-of-the box;
* rails tests were silently not running in CI;
* The CI suite was revamped, so that all Oauth tests would be run under rails as well. All versions from rails equal or above 5.0 are now targeted;

### 0.3.0

#### Features

* `oauth_refresh_token_protection_policy` is a new option, which can be used to set a protection policy around usage of refresh tokens. By default it's `none`, for backwards-compatibility. However, when set to `rotation`, refresh tokens will be "use-once", i.e. a token refresh request will generate a new refresh token. Also,  refresh token requests performed with already-used refresh tokens will be interpreted as a security breach, i.e. all tokens linked to the compromised refresh token will be revoked.

#### Improvements


* Support for the OIDC authorize [`prompt` parameter](https://openid.net/specs/openid-connect-core-1_0.html) (sectionn 3.1.2.1). It supports the `none`, `login` and `consent` out-of-the-box, while providing support for `select-account` when paired with [rodauth-select-account, a rodauth feature to handle multiple accounts in the same session](https://gitlab.com/honeyryderchuck/rodauth-select-account).

* Refresh Tokens are now expirable. The refresh token expiration period is governed by the `oauth_refresh_token_expires_in` option (default: 1 year), and is the period for which a refresh token can be used after its respective access token expired.

#### Bugfixes

* Default Templates now being packaged, as a way to provide a default experience to the OAuth journeys.

* fixing metadata urls when plugin loaded with a prefix path (@ianks)

* All date/time-based calculations, such as determining an expiration date, or checking if a token has expired, are now performed using database arithmetic operations, using sequel's `date_arithmetic` plugin. This will eliminate subtle bugs, such as when the database timezone is different than the application OS timezone.

* OIDC configuration endpoint is now stricter, eliminating JSON metadata inherited from the Oauth metadata endpoint. (@ianks)

#### Chore

Use `rodauth.convert_timestamp` in the templates, whenever dates are displayed.

Set HTTP Cache headers for metadata responses, such as `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration`, so they can be stored at the edge. The cache will be valid for 1 day (this value isn't set by an option yet).

### 0.2.0

#### Features

##### SAML Assertion Grant Type

`rodauth-auth` now supports using a SAML Assertion to request for an Access token.In order to enable, you have to:

```ruby
plugin :rodauth do
  enable :oauth_saml
end
```

For more info about integrating it, [check the wiki](https://gitlab.com/honeyryderchuck/rodauth-oauth/-/wikis/SAML-Assertion-Access-Tokens).

##### Supporting rotating keys

At some point, you'll want to replace the pkeys and algorithm used to generate and verify the JWT access tokens, but you want to keep validating previously-distributed JWT tokens, at least until they expire. Now you can, via two new options, `oauth_jwt_legacy_public_key` and `oauth_jwt_legacy_algorithm`, which will be declared in the JWKs URI and used to verify access tokens.


##### Reuse access tokens

If the `oauth_reuse_access_token` is set, if there's already an existing valid access token, any new grant for the same application / account / scope will keep the same access token. This can be helpful in scenarios where one wants the same access token distributed across devices.

##### require_authorizable_account

The method used to verify access to the authorize flow is called `require_authorizable_account`. By default, it checks if a user is logged in by using rodauth's own `require_account`. This is the method you'd want to redefine in order to augment these requirements, i.e. request 2fa authentication.

#### Improvements

Expired and revoked access tokens end up generating a lot of garbage, which will have to be periodically cleaned up. You can mitigate this now by setting a uniqueness index for a group of columns, i.e. if you set a uniqueness index for the `oauth_application_id/account_id/scopes` column, `rodauth-oauth` will transparently reuse the same db entry to store the new access token. If setting some other type of uniqueness index, make sure to update the option `oauth_tokens_unique_columns` (the array of columns from the uniqueness index).

#### Bugfixes

Calling `before_*_route` callbacks appropriately.

Fixed some mishandling of HTTP headers when in in resource-server mode.

#### Chore

* 97.7% test coverage;
* `rodauth-oauth` CI tests run against sqlite, postgresql and mysql.

### 0.1.0

(31/7/2020)

#### Features

##### OpenID

`rodauth-oauth` now ships with support for [OpenID Connect](https://openid.net/connect/). In order to enable, you have to:

```ruby
plugin :rodauth do
  enable :oidc
end
```

For more info about integrating it, [check the wiki](https://gitlab.com/honeyryderchuck/rodauth-oauth/-/wikis/home#openid-connect-since-v01).

It supports omniauth openID integrations out-of-the-box, [check the OpenID example, which integrates with omniauth_openid_connect](https://gitlab.com/honeyryderchuck/rodauth-oauth/-/tree/master/examples).

#### Improvements

* JWT: `sub` claim now also handles "pairwise" subjects. For that, you have to set the `oauth_jwt_subject_type` option (`"public"` or `"pairwise"`) and `oauth_jwt_subject_secret` (will be used for salting the `sub` when the type is `"pairwise"`).
* JWT: `auth_time` claim is now supported; if your application uses the `rodauth` feature `:account_expiration`, it'll use the `last_account_login_at` method, otherwise you can set the `last_account_login_at` option:

```ruby
last_account_login_at do
  convert_timestamp(db[accounts_table].where(account_id_column => account_id).get(:that_column_where_you_keep_the_data))
end
```
* JWT: `iss` claim now defaults to `authorization_server_url` when not defined;
* JWT: `aud` claim now defaults to the token application's client ID (`client_id` claim was removed as a result);



#### Breaking Changes

`rodauth-oauth` URLs no longer have the `oauth-` prefix, so make sure you update your integrations accordingly, i.e. where you used to rely on `/oauth-authorize`, you'll have to use `/authorize`.

URI schemes for client applications redirect URIs have to be `https`. In order to override this, set the `oauth_valid_uri_schemes` to an array of your expected URI schemes.


#### Bugfixes

* Authorization request submission can receive the `scope` as an array of values now, instead of only dealing with receiving a white-space separated list.
* fixed trailing "/" in the "issuer" value in server metadata (`https://server.com/` -> `https://server.com`).


### 0.0.6

(6/7/2020)

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


### 0.0.5

(26/6/2020)

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

## 0.0.4

(13/6/2020)

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

## 0.0.3

(5/6/2020)

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

## 0.0.2

(29/5/2020)

### Features

* Implementation of PKCE by OAuth Public Clients (https://tools.ietf.org/html/rfc7636);
* Implementation of grants using "access_type" and "approval_prompt" ([similar to what Google OAuth 2.0 API does](https://wiki.scn.sap.com/wiki/display/Security/Access+Google+APIs+using+the+OAuth+2.0+Client+API));

### Improvements

* Store token/refresh token hashes in the database, instead of the "plain" tokens;
* Client secret hashed by default, and provided by the application owner;

### Fix

* usage of client secret for authorizing the generation of tokens, as the spec mandates (and refraining from them when doing PKCE).

## 0.0.1

(14/5/2020)

Initial implementation of the Oauth 2.0 framework, with an example app done using roda.