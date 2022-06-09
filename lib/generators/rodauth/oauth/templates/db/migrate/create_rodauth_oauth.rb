class CreateRodauthOauth < ActiveRecord::Migration<%= migration_version %>
  def change
    create_table :oauth_applications do |t|
      t.integer :account_id
      t.foreign_key :accounts, column: :account_id
      t.string :name, null: false
      t.string :description, null: false
      t.string :homepage_url, null: false
      t.string :redirect_uri, null: false
      t.string :client_id, null: false, index: { unique: true }
      t.string :client_secret, null: false, index: { unique: true }
      t.string :scopes, null: false
      t.datetime :created_at, null: false, default: -> { "CURRENT_TIMESTAMP" }
      # extra params
      # t.string :token_endpoint_auth_method, null: true
      # t.string :grant_types, null: true
      # t.string :response_types, null: true
      # t.string :client_uri, null: true
      # t.string :logo_uri, null: true
      # t.string :tos_uri, null: true
      # t.string :policy_uri, null: true
      # t.string :jwks_uri, null: true
      # t.string :jwks, null: true
      # t.string :contacts, null: true
      # t.string :software_id, null: true
      # t.string :software_version, null: true
      # JWT/OIDC per application signing verification
      # t.text :jwt_public_key, null: true
      # RP-initiated logout
      # t.string :post_logout_redirect_uri, null: false
    end

    create_table :oauth_grants do |t|
      t.integer :account_id
      t.foreign_key :accounts, column: :account_id
      t.integer :oauth_application_id
      t.foreign_key :oauth_applications, column: :oauth_application_id
      t.string :code, null: false
      t.index(%i[oauth_application_id code], unique: true)
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
      # uncomment to use OIDC nonce
      # t.string :nonce
      # device code grant
      # t.string :user_code, null: true, unique: true
      # t.datetime :last_polled_at, null: true
      # when using :oauth_resource_indicators feature
      # t.string :resource
    end

    create_table :oauth_tokens do |t|
      t.integer :account_id
      t.foreign_key :accounts, column: :account_id
      t.integer :oauth_grant_id
      t.foreign_key :oauth_grants, column: :oauth_grant_id
      t.integer :oauth_token_id
      t.foreign_key :oauth_tokens, column: :oauth_token_id
      t.integer :oauth_application_id
      t.foreign_key :oauth_applications, column: :oauth_application_id
      t.string :token, null: false, token: true, unique: true
      # uncomment if setting oauth_tokens_token_hash_column
      # and delete the token column
      # t.string :token_hash, token: true, unique: true
      t.string :refresh_token, unique: true
      # uncomment if setting oauth_tokens_refresh_token_hash_column
      # and delete the refresh_token column
      # t.string :refresh_token_hash, token: true, unique: true
      t.datetime :expires_in, null: false
      t.datetime :revoked_at
      t.string :scopes, null: false
      t.datetime :created_at, null: false, default: -> { "CURRENT_TIMESTAMP" }
      # uncomment to use OIDC nonce
      # t.string :nonce
      # t.datetime :auth_time
      # when using :oauth_resource_indicators feature
      # t.string :resource
    end
  end
end