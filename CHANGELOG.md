# CHANGELOG

## master

### Features

* Implementation of PKCE by OAuth Public Clients (https://tools.ietf.org/html/rfc7636).

### Fix

* usage of client secret for authorizing the generation of tokens, as the spec mandates (and refraining from them when doing PKCE).

## 0.0.1

Initial implementation of the Oauth 2.0 framework, with an example app done using roda.