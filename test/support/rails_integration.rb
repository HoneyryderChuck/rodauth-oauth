# frozen_string_literal: true

ENV["RAILS_ENV"] = "test"

require_relative File.join(__dir__, "roda_integration")
# for rails integration tests
require_relative "../rails_app/config/environment"
require "rails/test_help"

ActiveRecord::Migrator.migrations_paths = [Rails.root.join("db/migrate")]
Rails.backtrace_cleaner.remove_silencers! # show full stack traces
if ActiveRecord.version >= Gem::Version.new("5.2.0")
  ActiveRecord::Base.connection.migration_context.up
else
  ActiveRecord::Migrator.up(Rails.application.paths["db/migrate"].to_a)
end

class RailsIntegrationTest < RodaIntegration
  include OAuthHelpers
  include Minitest::Hooks
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

  def logout
    visit "/logout"
    click_on "Logout"
  end

  def around
    ActiveRecord::Base.connection.begin_transaction(joinable: false) do
      hash = BCrypt::Password.create("0123456789", cost: BCrypt::Engine::MIN_COST)
      db[:accounts].insert(email: "foo@example.com", ph: hash)
      self.app = Rails.application

      Rmethod(__method__).super_method.call

      ActiveRecord::Base.connection.rollback_db_transaction
    end
  end

  def db
    DB
  end
end
