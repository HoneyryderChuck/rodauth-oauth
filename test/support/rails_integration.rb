# frozen_string_literal: true

ENV["RAILS_ENV"] = "test"

# for rails integration tests
require_relative "../rails_app/config/environment"
require "rails/test_help"

ActiveRecord::Migrator.migrations_paths = [Rails.root.join("db/migrate")]
Rails.backtrace_cleaner.remove_silencers! # show full stack traces

class RailsIntegrationTest < Minitest::Test
  include OAuthHelpers
  include Capybara::DSL

  def setup_application
    # eager load the application
    oauth_application
  end

  def register(login: "foo@example.com", password: "secret")
    visit "/create-account"
    fill_in "Login", with: login
    fill_in "Password", with: password
    fill_in "Confirm Password", with: password
    click_on "Create Account"
  end

  def login(login: "foo@example.com", password: "0123456789")
    visit "/login"
    fill_in "Login", with: login
    fill_in "Password", with: password
    click_on "Login"
  end

  def logout
    visit "/logout"
    click_on "Logout"
  end

  def setup
    super
    self.app = Rails.application
    if ActiveRecord.version >= Gem::Version.new("5.2.0")
      ActiveRecord::Base.connection.migration_context.up
    else
      ActiveRecord::Migrator.up(Rails.application.paths["db/migrate"].to_a)
    end
    hash = BCrypt::Password.create("0123456789", cost: BCrypt::Engine::MIN_COST)
    db[:accounts].insert(email: "foo@example.com", ph: hash)
  end

  def teardown
    super
    if ActiveRecord.version >= Gem::Version.new("5.2.0")
      ActiveRecord::Base.connection.migration_context.down
    else
      ActiveRecord::Migrator.down(Rails.application.paths["db/migrate"].to_a)
    end
    Capybara.reset_sessions!
    Capybara.use_default_driver
  end

  def db
    DB
  end
end
