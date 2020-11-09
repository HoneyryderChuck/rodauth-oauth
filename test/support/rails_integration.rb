# frozen_string_literal: true

ENV["RAILS_ENV"] = "test"

require_relative File.join(__dir__, "roda_integration")
# for rails integration tests
require_relative "../rails_app/config/environment"
require "rails/test_help"

DBRails.loggers << Logger.new($stderr) if ENV.key?("RODAUTH_DEBUG")
Sequel.extension :migration
require "rodauth/migrations"
Sequel::Migrator.run(DBRails, "test/migrate")
DBRails

class RailsIntegrationTest < RodaIntegration
  def setup_application
    # eager load the application
    oauth_application
    self.app = Rails.application
  end

  def register(login: "foo@example.com", password: "secret")
    visit "/create-account"
    fill_in "Login", with: login
    fill_in "Password", with: password
    fill_in "Confirm Password", with: password
    click_on "Create Account"
  end

  def logout
    visit "/logout"
    click_on "Logout"
  end

  def db
    DBRails
  end
end
