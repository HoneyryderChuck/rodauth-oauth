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
  gem "rails", ">= 4.2", "< 6.0"
  gem "sprockets", "< 4"
else
  gem "capybara", github: "teamcapybara/capybara", branch: "master"
  gem "json-jwt"
  gem "rails", ">= 4.2"

  # Docs/Website
  gem "hanna-nouveau", require: false
end

gem "roda"
gem "tilt"
gem "tzinfo-data"

# extension dependencies
gem "jwe"

# direct dependencies
gem "jwt", github: "jwt/ruby-jwt", branch: "master"
gem "rodauth"
gem "rodauth-rails"
gem "sequel"
gem "sequel-activerecord_connection"

# Demo-only
gem "omniauth_openid_connect"

# Tests/Debug
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
else
  gem "rubocop"
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
  # unblock if testing against a postgresql database
  # gem "pg"

  # For demo
  gem "erubi"
  gem "sassc"
end

platform :jruby do
  gem "activerecord-jdbc-adapter"
  gem "jdbc-sqlite3"
end
