# frozen_string_literal: true

require "rails/generators/base"
require "rails/generators/migration"
require "rails/generators/active_record"

module Rodauth
  module OAuth
    module Rails
      module Generators
        class InstallGenerator < ::Rails::Generators::Base
          include ::Rails::Generators::Migration

          source_root "#{__dir__}/templates"
          namespace "roda:oauth:install"

          def create_rodauth_migration
            return unless defined?(ActiveRecord::Base)

            migration_template "db/migrate/create_rodauth_oauth.rb", "db/migrate/create_rodauth_oauth.rb"
          end

          def create_oauth_models
            return unless defined?(ActiveRecord::Base)

            template "app/models/oauth_application.rb"
            template "app/models/oauth_grant.rb"
            template "app/models/oauth_token.rb"
          end

          private

          # required by #migration_template action
          def self.next_migration_number(dirname)
            ActiveRecord::Generators::Base.next_migration_number(dirname)
          end

          def migration_version
            if ActiveRecord.version >= Gem::Version.new("5.0.0")
              "[#{ActiveRecord::VERSION::MAJOR}.#{ActiveRecord::VERSION::MINOR}]"
            end
          end

          def adapter
            ActiveRecord::Base.connection_config.fetch(:adapter)
          end
        end
      end
    end
  end
end
