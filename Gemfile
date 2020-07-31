# frozen_string_literal: true

source "https://rubygems.org"

# Specify your gem's dependencies in roda-oauth.gemspec
gemspec

gem "rake", "~> 12.3"

gem "bcrypt"
gem "rack_csrf"

# frameworks
if RUBY_VERSION < "2.5"
  gem "capybara"
  gem "rails", ">= 4.2", "< 6.0"
else
  gem "capybara", github: "teamcapybara/capybara", branch: "master"
  gem "rails", ">= 4.2"

  # Docs/Website
  gem "hanna-nouveau", require: false
end

gem "roda"
gem "tilt"
gem "tzinfo-data"

# extension dependencies
gem "json-jwt"
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
gem "simplecov"
gem "webmock"

gem "rubocop"

gem "pry"
platform :mri do
  if RUBY_VERSION < "2.5"
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
