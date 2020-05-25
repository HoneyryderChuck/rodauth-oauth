# Roda::Oauth

[![pipeline status](https://gitlab.com/honeyryderchuck/roda-oauth/badges/master/pipeline.svg)](https://gitlab.com/honeyryderchuck/roda-oauth/-/commits/master)
[![coverage report](https://gitlab.com/honeyryderchuck/roda-oauth/badges/master/coverage.svg)](https://gitlab.com/honeyryderchuck/roda-oauth/-/commits/master)

This is an extension to the `rodauth` gem which adds support for the [OAuth 2.0 protocol](https://tools.ietf.org/html/rfc6749).

## Features

This gem implements:

* The OAuth 2.0 protocol framework:
  * Authorize flow;
  * Token generation;
  * Token refresh;
  * Token revocation;
  * Implicit grant (off by default);
* Access Type (Token refresh online and offline);
* OAuth application and token management dashboards;


This gem supports also rails (through [rodauth-rails]((https://github.com/janko/rodauth-rails))).


## Installation

Add this line to your application's Gemfile:

```ruby
gem 'roda-oauth'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install roda-oauth

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

If you're familiar with the technology and want to skip the next paragraphs, just [check our roda example](https://gitlab.com/honeyryderchuck/roda-oauth/-/tree/master/examples/roda).


Generating tokens happens mostly server-to-server, so here's an example using:

#### HTTPX

```ruby
require "httpx"
httpx = HTTPX.plugin(:authorization)
response = httpx.with(headers: { "X-your-auth-scheme" => ENV["SERVER_KEY"] })
                .post(json: {
                  client_id: ENV["OAUTH_CLIENT_ID"],
                  grant_type: "authorization_code",
                  code: "oiweicnewdh32fhoi3hf3ihfo2ih3f2o3as"
                })
response.raise_for_status
payload = JSON.parse(response.to_s)
puts payload #=> {"token" => "awr23f3h8f9d2h89...", "refresh_token" => "23fkop3kr290kc..." ....
```

#### cURL

```
> curl -H "X-your-auth-scheme: $SERVER_KEY" --data '{"client_id":"$OAUTH_CLIENT_ID","grant_type":"authorization_code","code":"oiweicnewdh32fhoi3hf3ihfo2ih3f2o3as"}'
```

### Database migrations

You have to generate database tables for Oauth applications, grants and tokens. In order for you to hit the ground running, [here's a set of migrations (using `sequel`) to generate the needed tables](https://gitlab.com/honeyryderchuck/roda-oauth/-/tree/master/test/migrate) (omit the first 2 if you already have account tables).

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
# create a migration file into db/migrate
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


## Development

After checking out the repo, run `bundle install` to install dependencies. Then, run `rake test` to run the tests, and `rake rubocop` to run thew linter.

## Contributing

Bug reports and pull requests are welcome on Gitlab at https://gitlab.com/honeyryderchuck/roda-oauth.

