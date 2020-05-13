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

This tutorial assumes you already read the documentation and know how to set up `rodauth`. After that, it's as simple as:

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

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/roda-oauth.

