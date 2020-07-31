# frozen_string_literal: true

source "https://rubygems.org"

# Specify your gem's dependencies in roda-oauth.gemspec
gemspec

gem "rake", "~> 12.3"

gem "bcrypt"
gem "rack_csrf"

# frameworks
gem "rails", ">= 4.2"
gem "roda"
gem "tilt"
gem "tzinfo-data"

# extension dependencies
gem "json-jwt"
gem "jwe"

# direct dependencies
gem "jwt", github: "jwt/ruby-jwt", branch: "master"
gem "rodauth", github: "jeremyevans/rodauth", branch: "master"
gem "rodauth-rails"
gem "sequel", github: "jeremyevans/sequel", branch: "master"
gem "sequel-activerecord_connection", github: "janko/sequel-activerecord_connection", branch: "master"

# Demo-only
gem "omniauth_openid_connect"

# Tests/Debug
if RUBY_VERSION < "2.5"
  gem "capybara"
else
  gem "capybara", github: "teamcapybara/capybara", branch: "master"
end

gem "minitest", "~> 5.0"
gem "minitest-hooks"
gem "rack-test"
gem "simplecov"
gem "webmock"

gem "rubocop"

gem "pry"
platform :mri do
  gem "pry-byebug"
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

# Docs/Website
gem "hanna-nouveau", require: false
