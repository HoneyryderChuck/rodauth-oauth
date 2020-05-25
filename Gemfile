# frozen_string_literal: true

source "https://rubygems.org"

# Specify your gem's dependencies in roda-oauth.gemspec
gemspec

gem "rake", "~> 12.0"

gem "bcrypt"
gem "rack_csrf"

# frameworks
gem "rails", ">= 4.2"
gem "roda"

# extension dependencies
gem "rodauth", github: "janko/rodauth", branch: "check-csrf-method"
gem "rodauth-rails"
gem "sequel", github: "jeremyevans/sequel", branch: "master"
gem "sequel-activerecord_connection", github: "HoneyryderChuck/sequel-activerecord_connection", branch: "patch-1"
gem "tilt"
gem "tzinfo-data"

gem "capybara"
gem "minitest", "~> 5.0"
gem "minitest-hooks"
gem "rack-test"
gem "simplecov"

gem "rubocop"

gem "pry"
platform :mri do
  gem "pry-byebug"
  gem "sqlite3"
end

platform :jruby do
  gem "jdbc-sqlite3"
end

# For demo
gem "erubi"
