# CHANGELOG

## master

### Features

* Implementation of PKCE by OAuth Public Clients (https://tools.ietf.org/html/rfc7636);
* Implementation of grants using "access_type" and "approval_prompt" ([similar to what Google OAuth 2.0 API does](https://wiki.scn.sap.com/wiki/display/Security/Access+Google+APIs+using+the+OAuth+2.0+Client+API));

### Improvements

* Store token/refresh token hashes in the database, instead of the "plain" tokens;
* Client secret hashed by default, and provided by the application owner;

### Fix

* usage of client secret for authorizing the generation of tokens, as the spec mandates (and refraining from them when doing PKCE).

## 0.0.1

Initial implementation of the Oauth 2.0 framework, with an example app done using roda.