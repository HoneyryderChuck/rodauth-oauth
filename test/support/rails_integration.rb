# frozen_string_literal: true

begin
  require "rails"
rescue LoadError
else
  ENV["RAILS_ENV"] = "test"
  ENV["DATABASE_URL"] ||= "sqlite3::memory:"

  require_relative File.join(__dir__, "roda_integration")
  # for rails integration tests
  require_relative "../rails_app/config/environment"
  require "rails/test_help"

  Sequel::Migrator.run(RAILSDB, "test/migrate")

  class RodaIntegration
    def roda(type = nil, &block)
      jwt_only = type == :jwt

      app = Class.new(Rodauth::Rails::App) do
        def self.constantize
          self
        end
      end
      rodauth_blocks = @rodauth_blocks

      opts = rodauth_opts(type)

      opts[:json] = jwt_only ? :only : true

      app.plugin :render, views: "test/views"
      app.configure(nil, opts) do
        # OAuth
        rodauth_blocks.reverse_each do |rodauth_block|
          instance_exec(&rodauth_block)
        end

        account_password_hash_column :ph
        db RAILSDB
        rails_controller { RodauthController }
        skip_status_checks? true
      end
      app.route(&block)

      Rodauth::Rails.app = app

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
      RAILSDB
    end
  end
end
