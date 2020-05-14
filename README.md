# Roda::Oauth


This is an extension to the `rodauth` gem which adds support for the OAuth 2.0 protocol.

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
* `GET /oauth-applications/new`: returns a new OAuth application form;
* `POST /oauth-applications`: processes a new OAuth application request;

As in the OAuth authorization form example, you'll have to define the following HTML templates in order to use this feature:

* `oauth_applications.(erb|str|...)`: the list of OAuth applications;
* `oauth_application.(erb|str|...)`: the OAuth application page;
* `new_oauth_application.(erb|str|...)`: the new OAuth application form;

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/roda-oauth.

