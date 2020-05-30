# Rodauth::Oauth

[![pipeline status](https://gitlab.com/honeyryderchuck/rodauth-oauth/badges/master/pipeline.svg)](https://gitlab.com/honeyryderchuck/rodauth-oauth/-/commits/master)
[![coverage report](https://gitlab.com/honeyryderchuck/rodauth-oauth/badges/master/coverage.svg)](https://gitlab.com/honeyryderchuck/rodauth-oauth/-/commits/master)

This is an extension to the `rodauth` gem which implements the [OAuth 2.0 framework](https://tools.ietf.org/html/rfc6749) for an authorization server.

## Features

This gem implements:

* [The OAuth 2.0 protocol framework](https://tools.ietf.org/html/rfc6749):
  * [Authorization grant flow](https://tools.ietf.org/html/rfc6749#section-1.3);
  * [Access Token generation](https://tools.ietf.org/html/rfc6749#section-1.4);
  * [Access Token refresh](https://tools.ietf.org/html/rfc6749#section-1.5);
  * [Token revocation](https://tools.ietf.org/html/rfc7009);
  * [Implicit grant (off by default)[https://tools.ietf.org/html/rfc6749#section-4.2];
  * [PKCE](https://tools.ietf.org/html/rfc7636);
* Access Type (Token refresh online and offline);
* OAuth application and token management dashboards;


This gem supports also rails (through [rodauth-rails]((https://github.com/janko/rodauth-rails))).


## Installation

Add this line to your application's Gemfile:

```ruby
gem 'rodauth-oauth'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install rodauth-oauth

## Usage

This tutorial assumes you already read the documentation and know how to set up `rodauth`. After that, integrating `roda-auth` will look like:

```ruby
plugin :rodauth do
  # enable it in the plugin
  enable :login, :oauth
  oauth_application_default_scope %w[profile.read]
  oauth_application_scopes %w[profile.read profile.write]
end

# then, inside roda

route do |r|
  r.rodauth

  # public routes go here
  # ...
  # here you do your thing
  # authenticated section is here

  rodauth.require_authentication

  # oauth will only kick in on ce you call #require_oauth_authorization

  r.is "users" do
    rodauth.require_oauth_authorization # defaults to profile.read
    r.post do
      rodauth.require_oauth_authorization("profile.write")
    end
    # ...
  end

  r.is "books" do
    rodauth.require_oauth_authorization("books.read", "books.research")
    r.get do
      # ...
    end
  end
end
```

You'll have to do a bit more boilerplate, so here's the instructions.

### Example (TL;DR)

If you're familiar with the technology and want to skip the next paragraphs, just [check our roda example](https://gitlab.com/honeyryderchuck/rodauth-oauth/-/tree/master/examples/roda).


Generating tokens happens mostly server-to-server, so here's an example using:

#### Access Token Generation

##### HTTPX

```ruby
require "httpx"
response = HTTPX.post("https://auth_server/oauth-token",json: {
                  client_id: ENV["OAUTH_CLIENT_ID"],
                  client_secret: ENV["OAUTH_CLIENT_SECRET"],
                  grant_type: "authorization_code",
                  code: "oiweicnewdh32fhoi3hf3ihfo2ih3f2o3as"
                })
response.raise_for_status
payload = JSON.parse(response.to_s)
puts payload #=> {"token" => "awr23f3h8f9d2h89...", "refresh_token" => "23fkop3kr290kc..." ....
```

##### cURL

```
> curl --data '{"client_id":"$OAUTH_CLIENT_ID","client_secret":"$OAUTH_CLIENT_SECRET","grant_type":"authorization_code","code":"oiweicnewdh32fhoi3hf3ihfo2ih3f2o3as"}' https://auth_server/oauth-token
```

#### Refresh Token

Refreshing expired tokens also happens mostly server-to-server, here's an example:

##### HTTPX

```ruby
require "httpx"
response = HTTPX.post("https://auth_server/oauth-token",json: {
                  client_id: ENV["OAUTH_CLIENT_ID"],
                  client_secret: ENV["OAUTH_CLIENT_SECRET"],
                  grant_type: "refresh_token",
                  token: "2r89hfef4j9f90d2j2390jf390g"
                })
response.raise_for_status
payload = JSON.parse(response.to_s)
puts payload #=> {"token" => "awr23f3h8f9d2h89...", "token_type" => "Bearer" ....
```

##### cURL

```
> curl -H "X-your-auth-scheme: $SERVER_KEY" --data '{"client_id":"$OAUTH_CLIENT_ID","client_secret":"$OAUTH_CLIENT_SECRET","grant_type":"token","token":"2r89hfef4j9f90d2j2390jf390g"}' https://auth_server/oauth-token
```

#### Revoking tokens

Token revocation can be done both by the idenntity owner or the application owner, and can therefore be done either online (browser-based form) or server-to-server. Here's an example using server-to-server:

```ruby
require "httpx"
httpx = HTTPX.plugin(:authorization)
response = httpx.with(headers: { "X-your-auth-scheme" => ENV["SERVER_KEY"] })
                .post("https://auth_server/oauth-revoke",json: {
                  client_id: ENV["OAUTH_CLIENT_ID"],
                  token_type_hint: "access_token", # can also be "refresh:tokn"
                  token: "2r89hfef4j9f90d2j2390jf390g"
                })
response.raise_for_status
payload = JSON.parse(response.to_s)
puts payload #=> {"token" => "awr23f3h8f9d2h89...", "token_type" => "Bearer" ....
```

##### cURL

```
> curl -H "X-your-auth-scheme: $SERVER_KEY" --data '{"client_id":"$OAUTH_CLIENT_ID","token_type_hint":"access_token","token":"2r89hfef4j9f90d2j2390jf390g"}' https://auth_server/oauth-revoke
```

### Database migrations

You have to generate database tables for Oauth applications, grants and tokens. In order for you to hit the ground running, [here's a set of migrations (using `sequel`) to generate the needed tables](https://gitlab.com/honeyryderchuck/rodauth-oauth/-/tree/master/test/migrate) (omit the first 2 if you already have account tables).

You can change column names or even use existing tables, however, be aware that you'll have to define new column accessors at the `rodauth` plugin declaration level. Let's say, for instance, you'd like to change the `oauth_grants` table name to `access_grants`, and it's `code` column to `authorization_code`; then, you'd have to do the following:

```ruby
plugin :rodauth do
  # enable it in the plugin
  enable :login, :oauth
  # ...
  oauth_grants_table "access_grants"
  oauth_grants_code_column "authorization_code"
end
```

If you're starting from scratch though, the recommendation is to stick to the defaults.

### HTML views

You'll have to generate HTML templates for the Oauth Authorization form.

The rodauth default setup expects the roda `render` plugin to be activated; by default, it expects a `views` directory to be defined in the project root folder. The Oauth Authorization template must be therefore defined there, and it should be called `oauth_authorize.(erb|str|...)` (read the [roda `render` plugin documentation](http://roda.jeremyevans.net/rdoc/classes/Roda/RodaPlugins/Render.html) for more info about HTML templating).

### Endpoints

Once you set it up, by default, the following endpoints will be available:

* `GET /oauth-authorize`: Loads the OAuth authorization HTML form;
* `POST /oauth-authorize`: Responds to an OAuth authorization request, as [per the spec](https://tools.ietf.org/html/rfc6749#section-4);
* `POST /oauth-token`: Generates OAuth tokens as [per the spec](https://tools.ietf.org/html/rfc6749#section-4.4.2);
* `POST /oauth-revoke`: Revokes OAuth tokens as [per the spec](https://tools.ietf.org/html/rfc7009);

### OAuth applications

This feature is **optional**, as not all authorization servers will want a full oauth applications dashboard. However, if you do and you don't want to do the work yourself, you can set it up in your roda app like this:

```ruby
route do |r|
  r.rodauth
  # don't forget to authenticate to access the dashboard
  rodauth.require_authentication
  rodauth.oauth_applications
  # ...
end
```

This will define the following endpoints:

* `GET /oauth-applications`: returns the OAuth applications HTML dashboard;
* `GET /oauth-applications/{application_id}`: returns an OAuth application HTML page;
* `GET /oauth-applications/{application_id}/oauth-tokens`: returns the OAuth tokens from an OAuth application HTML page;
* `GET /oauth-applications/new`: returns a new OAuth application form;
* `POST /oauth-applications`: processes a new OAuth application request;

As in the OAuth authorization form example, you'll have to define the following HTML templates in order to use this feature:

* `oauth_applications.(erb|str|...)`: the list of OAuth applications;
* `oauth_application.(erb|str|...)`: the OAuth application page;
* `new_oauth_application.(erb|str|...)`: the new OAuth application form;
* `oauth_tokens.(erb|str|...)`: the list of OAuth tokens from an application;

## Rails

This library provides a thin integration layer on top of [rodauth-rails](https://github.com/janko/rodauth-rails). Therefore, the first step you'll have to take is to integrate it in your project. Fortunately, it's very straightforward.

You'll have to run the generator task to create the necessary migrations and views:

```
> bundle exec rails generate rodauth:oauth:install
# create a migration file, db/migrate(*_create_rodauth_oauth.rb);
# Oauth Application, Grant and Token models into app/models;
> bundle exec rails generate rodauth:oauth:views
# creates view files under app/views/rodauth
```

You are encouraged to check the output and adapt it to your needs.

You can then enable this feature in `lib/rodauth_app.rb` and set up any options you want:

```ruby
# lib/roudauth_app.rb
enable :oauth
# OAuth
oauth_application_default_scope "profile.read"
oauth_application_scopes %w[profile.read profile.write books.read books.write]
```

Now that you're set up, you can use the `rodauth` object to deny access to certain subsets of your app/API:

```ruby
class BooksController < ApplicationController
  before_action :allow_read_access, only: %i[index show]
  before_action :allow_write_access, only: %i[create update]

  def index
    # ...
  end

  def show
    # ...
  end

  def create
    # ...
  end

  def update
    # ...
  end

  private

  def allow_read_access
    rodauth.require_oauth_authorization("books.read")
  end

  def allow_write_access
    rodauth.require_oauth_authorization("books.write")
  end
end
```

## Features

In this section, the non-standard features are going to be described in more detail.

### Token / Secrets Hashing

Although not human-friendly as passwords, for security reasons, you might not want to store access (and refresh) tokens in the database. If that is the case, You'll have to add the respective hash columns in the table:

```ruby
# in migration
String :token_hash, null: false, token: true
String :refresh_token_hash, token, true
# and you DO NOT NEED the token and refresh_token columns anymore!
```

And declare them in the plugin:

```ruby
plugin :rodauth do
  enable :oauth
  oauth_tokens_token_hash_column :token_hash
  oauth_tokens_token_hash_column :refresh_token_hash
```

#### Client Secret

By default, it's expected that the "client secret" property from an OAuth application is only known by the owner, and only the hash is stored in the database; this way, the authorization server doesn't know what the client secret is, only the application owner. The provided [OAuth Applications Extensions](#oauth-applications) application form contains a "Client Secret" input field for this reason.

However, this extension is optional, and you might want to generate the secrets and store them as is. In that case, you'll have to re-define some options:

```ruby
plugin :rodauth do
  enable :oauth
  secret_matches? ->(application, secret){ application[:client_secret] == secret }
end
```

### Access Type (default: "offline")

The "access_type" feature allows the authorization server to emit access tokens with no associated refresh token. This means that users with expired access tokens will have to go through the OAuth flow everytime they need a new one.

In order to enable this option, add "access_type=online" to the query params section of the authorization url.

#### Approval Prompt

When using "online grants", one can use an extra query param in the URL, "approval_prompt", which when set to "auto", will skip the authorization form (on the other hand, if one wants to force the authorization form for all grants, then you can set it to "force", or don't set it at all, as it's the default).

This will only work **if there was a previous successful online grant** for the same application, scopes and redirect URI.

#### DB schema

the "oauth_grants" table will have to include the "access_type row":

```ruby
# in migration
String :access_type, null: false, default: "offline"
```

If you want to disable this flow altogether, you can:

```ruby
enable :oauth
use_oauth_access_type? false
```


### Implicit Grant (default: disabled)

The implicit grant flow is part of the original OAuth 2.0 RFC, however, if you care about security, you are **strongly recommended** not to enable it.

However, if you really need it, just pass the option when enabling the `rodauth` plugin:

```ruby
plugin :rodauth do
  enable :oauth
  use_oauth_implicit_grant_type true
end
```

And add "response_type=token" to the query params section of the authorization url.

### PKCE

The "Proof Key for Code Exchange by OAuth Public Clients" (aka PKCE) flow, which is **particularly recommended for OAuth integration in mobile apps**, is transparently supported by `rodauth-oauth`, by adding the `code_challenge_method=S256&code_challenge=$YOUR_CODE_CHALLENGE` query params to the authorization url. Once you do that, you'll have to pass the `code_verifier` when generating a token:

```ruby
# with httpx
require "httpx"
httpx = HTTPX.plugin(:authorization)
response = httpx.with(headers: { "X-your-auth-scheme" => ENV["SERVER_KEY"] })
                .post("https://auth_server/oauth-token",json: {
                  client_id: ENV["OAUTH_CLIENT_ID"],
                  grant_type: "authorization_code",
                  code: "oiweicnewdh32fhoi3hf3ihfo2ih3f2o3as",
                  code_verifier: your_code_verifier_here
                })
response.raise_for_status
payload = JSON.parse(response.to_s)
puts payload #=> {"token" =
```

By default, the pkce integration sets "S256" as the default challenge method. If you value security, you **should not use plain**. However, if you really need to, you can set it in the `rodauth` plugin:

```ruby
plugin :rodauth do
  enable :oauth
  oauth_pkce_challenge_method "plain"
end
```

Although PKCE flow is supported out-of-the-box, it's not enforced by default. If you want to, you can force it, thereby forcing clients to generate a challenge:

```ruby
plugin :rodauth do
  enable :oauth
  oauth_require_pkce true
end
```

If you want, on the other hand. to disable this flow altogether, you can:

```ruby
enable :oauth
use_oauth_pkce? false
```

## Ruby support policy

The minimum Ruby version required to run `rodauth-oauth` is 2.3 . Besides that, it should support all rubies that rodauth and roda support.

### JRuby

If you're interested in using this library in rails, be warned that `rodauth-rails` doesn't support it yet (although, this is expected to change at some point).

## Development

After checking out the repo, run `bundle install` to install dependencies. Then, run `rake test` to run the tests, and `rake rubocop` to run the linter.

## Contributing

Bug reports and pull requests are welcome on Gitlab at https://gitlab.com/honeyryderchuck/rodauth-oauth.

