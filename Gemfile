# frozen_string_literal: true

source "https://rubygems.org"

# Specify your gem's dependencies in roda-oauth.gemspec
gemspec

gem "rake", "~> 12.3"

gem "bcrypt"
gem "rack_csrf"

# frameworks
if RUBY_VERSION < "2.6"
  gem "capybara", "~> 3.35.0"
else
  gem "capybara"
end

gem "rack"
gem "rackup"
gem "roda"
gem "tilt"
gem "tzinfo-data"

# extension dependencies
gem "jwe"

# direct dependencies
gem "json-jwt"
gem "jwt"
gem "rodauth", ">= 2.0.0"
gem "sequel"

# Demo-only
gem "omniauth_openid_connect" if RUBY_VERSION >= "2.7.0"

# Tests/Debug
gem "json-schema"
gem "minitest", "~> 5.0"
gem "minitest-hooks"
gem "rack-test"
gem "webmock"

gem "rodauth-i18n", ">= 0.2.0"
gem "rotp"
gem "rqrcode"
gem "ruby-saml"
gem "saml_idp"
gem "xmlenc"

gem "rodauth-select-account", "~> 0.0.2"
gem "rubocop"
gem "rubocop-performance"
gem "simplecov"

gem "pry"
platform :mri, :truffleruby do
  gem "pry-byebug"
  gem "sqlite3"
  gem "webauthn"

  gem "mysql2"
  gem "pg"
end

gem "rbs", platforms: :mri if RUBY_VERSION >= "3.0"

group :demo do
  # For demo
  gem "erubi"
  gem "sassc"
  gem "webrick" if RUBY_VERSION >= "3.0"
end

platform :jruby do
  gem "activerecord-jdbc-adapter"
  gem "jdbc-mysql"
  gem "jdbc-postgres"
  gem "jdbc-sqlite3"
end

if RUBY_VERSION >= "3.0.0"
  group :website do
    # Docs/Website
    gem "hanna-nouveau", require: false
  end
end
