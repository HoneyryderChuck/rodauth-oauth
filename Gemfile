# frozen_string_literal: true

source "https://rubygems.org"

# Specify your gem's dependencies in roda-oauth.gemspec
gemspec

gem "rake", "~> 12.0"

gem "bcrypt"
gem "rack_csrf"
gem "roda"
gem "rodauth"
gem "sequel"
gem "tilt"

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
  gem "activerecord-jdbcsqlite3-adapter"
end

# For demo
gem "erubi"
