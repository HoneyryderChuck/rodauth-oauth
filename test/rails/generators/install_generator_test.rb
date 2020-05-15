# frozen_string_literal: true

require "test_helper"
require "generators/roda/oauth/install_generator"

class InstallGeneratorTest < Rails::Generators::TestCase
  tests Rodauth::OAuth::Rails::Generators::InstallGenerator
  destination File.expand_path("#{__dir__}/../../tmp")
  setup :prepare_destination

  test "migration" do
    run_generator

    if ActiveRecord.version >= Gem::Version.new("5.0.0")
      migration_version = Regexp.escape("[#{ActiveRecord::VERSION::MAJOR}.#{ActiveRecord::VERSION::MINOR}]")
    end

    assert_migration "db/migrate/create_roda_oauth.rb", /class CreateRodaOAuth < ActiveRecord::Migration#{migration_version}/
    assert_migration "db/migrate/create_roda_oauth.rb", /create_table :oauth_applications/
    assert_migration "db/migrate/create_roda_oauth.rb", /create_table :oauth_grants/
    assert_migration "db/migrate/create_roda_oauth.rb", /create_table :oauth_tokens/
  end

  test "model" do
    run_generator

    assert_file "app/models/oauth_token.rb", /class OauthToken < ApplicationRecord/
    assert_file "app/models/oauth_grant.rb", /class OauthGrant < ApplicationRecord/
    assert_file "app/models/oauth_application.rb", /class OauthApplication < ApplicationRecord/
  end
end
