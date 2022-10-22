# frozen_string_literal: true

version = eval("#{::ActiveRecord::VERSION::MAJOR}.#{::ActiveRecord::VERSION::MINOR}")

superclass = if ActiveRecord.version >= Gem::Version.new("5.0.0")
               ActiveRecord::Migration[version]
             else
               ActiveRecord::Migration
             end

class CreateRodauthOauth < superclass
  def change
    create_table :oauth_applications do |t|
      t.integer :account_id
      t.foreign_key :accounts, column: :account_id
      t.string :name, null: false
      t.string :description, null: true
      t.string :homepage_url, null: true
      t.string :redirect_uri, null: false
      t.string :client_id, null: false, index: { unique: true }
      t.string :client_secret, null: false, index: { unique: true }
      t.string :scopes, null: false
      t.datetime :created_at, null: false, default: -> { "CURRENT_TIMESTAMP" }
    end unless table_exists?(:oauth_applications)

    create_table :oauth_grants do |t|
      t.integer :account_id
      t.foreign_key :accounts, column: :account_id
      t.integer :oauth_application_id
      t.foreign_key :oauth_applications, column: :oauth_application_id
      t.string :type, null: false
      t.string :code, null: false
      t.index(%i[oauth_application_id code], unique: true)
      t.string :token, null: false, token: true, unique: true
      # uncomment if setting oauth_grants_token_hash_column
      # and delete the token column
      # t.string :token_hash, token: true, unique: true
      t.string :refresh_token, unique: true
      # uncomment if setting oauth_grants_refresh_token_hash_column
      # and delete the refresh_token column
      # t.string :refresh_token_hash, token: true, unique: true
      t.datetime :expires_in, null: false
      t.string :redirect_uri
      t.datetime :revoked_at
      t.string :scopes, null: false
      t.datetime :created_at, null: false, default: -> { "CURRENT_TIMESTAMP" }
      # for using access_types
      t.string :access_type, null: false, default: "offline"
      # uncomment to enable PKCE
      # t.string :code_challenge
      # t.string :code_challenge_method
      t.index(%i[oauth_application_id code], unique: true)
    end unless table_exists?(:oauth_grants)
  end
end
