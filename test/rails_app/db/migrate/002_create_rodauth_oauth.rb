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
      t.string :homepage_url, null: false
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
      t.string :code, null: false
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

    create_table :oauth_tokens do |t|
      t.integer :account_id
      t.foreign_key :accounts, column: :account_id
      t.integer :oauth_grant_id
      t.foreign_key :oauth_grants, column: :oauth_grant_id
      t.integer :oauth_token_id
      t.foreign_key :oauth_tokens, column: :oauth_token_id
      t.integer :oauth_application_id
      t.foreign_key :oauth_applications, column: :oauth_application_id
      t.string :token, null: false, token: true
      t.string :refresh_token
      t.datetime :expires_in, null: false
      t.datetime :revoked_at
      t.string :scopes, null: false
      t.string :nonce
      t.string :acr
      t.datetime :created_at, null: false, default: -> { "CURRENT_TIMESTAMP" }
    end unless table_exists?(:oauth_tokens)
  end
end
