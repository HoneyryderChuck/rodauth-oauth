# Rodauth::Oauth

[![Gem Version](https://badge.fury.io/rb/rodauth-oauth.svg)](http://rubygems.org/gems/rodauth-oauth)
[![pipeline status](https://gitlab.com/honeyryderchuck/rodauth-oauth/badges/master/pipeline.svg)](https://gitlab.com/honeyryderchuck/rodauth-oauth/pipelines?page=1&scope=all&ref=master)
[![coverage report](https://gitlab.com/honeyryderchuck/rodauth-oauth/badges/master/coverage.svg?job=coverage)](https://honeyryderchuck.gitlab.io/rodauth-oauth/coverage/#_AllFiles)

This is an extension to the `rodauth` gem which implements the [OAuth 2.0 framework](https://tools.ietf.org/html/rfc6749) for an authorization server.

## Features

This gem implements the following RFCs and features of OAuth:

* `oauth` - [The OAuth 2.0 protocol framework](https://tools.ietf.org/html/rfc6749):
  * [Access Token generation](https://tools.ietf.org/html/rfc6749#section-1.4);
  * [Access Token refresh token grant](https://tools.ietf.org/html/rfc6749#section-1.5);
  * `oauth_authorization_code_grant` - [Authorization code grant](https://tools.ietf.org/html/rfc6749#section-1.3);
  * `oauth_implicit_grant` - [Implicit grant (off by default)](https://tools.ietf.org/html/rfc6749#section-4.2);
  * `oauth_client_credentials_grant` - [Client credentials grant (off by default)](https://tools.ietf.org/html/rfc6749#section-4.4);
  * `oauth_device_code_grant` - [Device code grant (off by default)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-device-flow-15);
  * `oauth_token_revocation` - [Token revocation](https://tools.ietf.org/html/rfc7009);
  * `oauth_token_introspection` - [Token introspection](https://tools.ietf.org/html/rfc7662);
  * [Authorization Server Metadata](https://tools.ietf.org/html/rfc8414);
  * `oauth_pkce` - [PKCE](https://tools.ietf.org/html/rfc7636);
  * `oauth_jwt` - [JWT Access Tokens](https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-07);
  * `oauth_jwt_secured_authorization_request` - [JWT Secured Authorization Request](https://tools.ietf.org/html/draft-ietf-oauth-jwsreq-20);
  * `oauth_resource_indicators` - [Resource Indicators](https://datatracker.ietf.org/doc/html/rfc8707);
  * Access Type (Token refresh online and offline);
* `oauth_http_mac` - [MAC Authentication Scheme](https://tools.ietf.org/html/draft-hammer-oauth-v2-mac-token-02);
* `oauth_assertion_base` - [Assertion Framework](https://datatracker.ietf.org/doc/html/rfc7521);
  * `oauth_saml_bearer_grant` - [SAML 2.0 Bearer Assertion](https://datatracker.ietf.org/doc/html/rfc7522);
  * `oauth_jwt_bearer_grant` - [JWT Bearer Assertion](https://datatracker.ietf.org/doc/html/rfc7523);

* `oauth_dynamic_client_registration` - [Dynamic Client Registration Protocol](https://datatracker.ietf.org/doc/html/rfc7591);
* OAuth application and token management dashboards;

It also implements the [OpenID Connect layer](https://openid.net/connect/) (via the `openid` feature) on top of the OAuth features it provides, including:

* [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html);
* [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0-29.html);
* [OpenID Multiple Response Types](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html);
* [OpenID Connect Dynamic Client Registration](https://openid.net/specs/openid-connect-registration-1_0.html);
* [RP Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html);

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


## Resources
|               |                                                             |
| ------------- | ----------------------------------------------------------- |
| Website       | https://honeyryderchuck.gitlab.io/rodauth-oauth/            |
| Documentation | https://honeyryderchuck.gitlab.io/rodauth-oauth/rdoc/       |
| Wiki          | https://gitlab.com/honeyryderchuck/rodauth-oauth/wikis/home |
| CI            | https://gitlab.com/honeyryderchuck/rodauth-oauth/pipelines  |

## Articles

* [How to use rodauth-oauth with rails and rodauth](https://honeyryderchuck.gitlab.io/httpx/2021/03/15/oidc-provider-on-rails-using-rodauth-oauth.html)
* [How to use rodauth-oauth with rails and without rodauth](https://honeyryderchuck.gitlab.io/httpx/2021/09/08/using-rodauth-oauth-in-rails-without-rodauth-based-auth.html)

## Usage

This tutorial assumes you already read the documentation and know how to set up `rodauth`. After that, integrating `rodauth-oauth` will look like:

```ruby
plugin :rodauth do
  # enable it in the plugin
  enable :login, :oauth
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


For OpenID, it's very similar to the example above:

```ruby
plugin :rodauth do
  # enable it in the plugin
  enable :login, :oidc
  oauth_application_scopes %w[openid email profile]
end
```


### Example (TL;DR)

Just [check our example applications](https://gitlab.com/honeyryderchuck/rodauth-oauth/-/tree/master/examples/).


### Database migrations

You have to generate database tables for accounts, oauth applications, grants and tokens. In order for you to hit the ground running, [here's a set of migrations (using `sequel`) to generate the needed tables](https://gitlab.com/honeyryderchuck/rodauth-oauth/-/tree/master/test/migrate) (omit the first 2 if you already have account tables, and [follow recommendations from rodauth accordingly](https://github.com/jeremyevans/rodauth)).

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

### OAuth applications management

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

Navigate to `"http://your-app/oauth-applications"` and click around.

## Rails

Support for `rails` is achieved thanks to [rodauth-rails](https://github.com/janko/rodauth-rails). Therefore, the first step you'll have to take is to add it to your dependencies.

You'll have to run the generator task to create the necessary migrations and views:

```
> bundle exec rails generate rodauth:oauth:install
# create a migration file, db/migrate(*_create_rodauth_oauth.rb);
# Oauth Application, Grant and Token models into app/models;
> bundle exec rails generate rodauth:oauth:views
# copies default view files into app/views/rodauth
```

You are encouraged to check the output and adapt it to your needs.

You can then enable this feature in `lib/rodauth_app.rb` and set up any options you want:

```ruby
# lib/roudauth_app.rb
enable :oauth
# OAuth
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
  enable :oauth_authorization_code_grant
  oauth_grants_token_hash_column :token_hash
  oauth_grants_token_hash_column :refresh_token_hash
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

#### Internationalization (i18n)

`rodauth-oauth` supports translating all user-facing text found in all pages and forms, by integrating with [rodauth-i18n](https://github.com/janko/rodauth-i18n). Just set it up in your application and `rodauth` configuration.

Default translations shipping with `rodauth-oauth` can be found [in this directory](https://gitlab.com/honeyryderchuck/rodauth-oauth/-/tree/master/locales). If they're not available for the languages you'd like to support, consider getting them translated from the english text, and contributing them to this repository via a Merge Request.

(This feature is available since `v0.7`.)


## Ruby support policy

The minimum Ruby version required to run `rodauth-oauth` is 2.3 . Besides that, it should support all rubies that rodauth and roda support, including JRuby and truffleruby.

### Rails

If you're interested in using this library with rails, be sure to check `rodauth-rails` policy, as it supports rails 5.2 upwards.

## Development

After checking out the repo, run `bundle install` to install dependencies. Then, run `rake test` to run the tests, and `rake rubocop` to run the linter.

## Contributing

Bug reports and pull requests are welcome on Gitlab at https://gitlab.com/honeyryderchuck/rodauth-oauth.
