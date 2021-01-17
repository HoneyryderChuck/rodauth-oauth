# frozen_string_literal: true

source "https://rubygems.org"

# Specify your gem's dependencies in roda-oauth.gemspec
gemspec

gem "rake", "~> 12.3"

gem "bcrypt"
gem "rack_csrf"

# frameworks
if RUBY_VERSION < "2.5"
  gem "capybara", "~> 3.15.0"
  gem "json-jwt", "~> 1.12.0"
elsif RUBY_VERSION < "2.6"
  gem "capybara", "~> 3.35.0"
  gem "json-jwt"
else
  gem "capybara"
  gem "json-jwt"
end

gem "roda"
gem "tilt"
gem "tzinfo-data"

# extension dependencies
gem "jwe"

# direct dependencies
gem "jwt", "~> 2.2.2"
gem "rodauth"
gem "sequel"

# Demo-only
gem "omniauth_openid_connect"

# Tests/Debug
gem "json-schema"
gem "minitest", "~> 5.0"
gem "minitest-hooks"
gem "rack-test"
gem "webmock"

gem "ruby-saml"
gem "saml_idp"
gem "xmlenc"

if RUBY_VERSION < "2.4"
  gem "rubocop", "~> 0.81.0"
  gem "simplecov", "< 0.18.0"
elsif RUBY_VERSION < "2.5"
  gem "rodauth-select-account", "~> 0.0.2"
  gem "rubocop", "~> 1.12.0"
  gem "rubocop-performance", "~> 1.10.2"
  gem "simplecov", "~> 0.18.0"
else
  gem "rodauth-select-account", "~> 0.0.2"
  gem "rubocop"
  gem "rubocop-performance"
  gem "simplecov"
end

gem "pry"
platform :mri do
  if RUBY_VERSION < "2.5"
    gem "byebug", "~> 11.0.1"
    gem "pry-byebug", "~> 3.7.0"
  else
    gem "pry-byebug"
  end
  gem "sqlite3"

  gem "mysql2"
  gem "pg"
end

gem "rbs" if RUBY_VERSION >= "3.0"

group :demo do
  # For demo
  gem "erubi"
  gem "sassc"

  gem "mysql2"
  gem "pg"
end

platform :jruby do
  gem "activerecord-jdbc-adapter"
  gem "jdbc-mysql"
  gem "jdbc-postgres"
  gem "jdbc-sqlite3"
end
