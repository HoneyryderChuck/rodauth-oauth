# frozen_string_literal: true

Sequel.migration do
  up do
    create_table :oauth_tokens do |_t|
      primary_key :id, type: Integer
      foreign_key :account_id, :accounts
      foreign_key :oauth_grant_id, :oauth_grants
      foreign_key :oauth_token_id, :oauth_tokens
      foreign_key :oauth_application_id, :oauth_applications, null: false
      String :token, token: true, unique: true
      # if hashed tokens
      String :token_hash, token: true, unique: true
      String :refresh_token, token: true, unique: true
      # if hashed tokens
      String :refresh_token_hash, token: true, unique: true
      Time :expires_in, null: false
      Time :revoked_at
      String :scopes, null: false
      String :nonce
      index %i[oauth_application_id account_id scopes], unique: true if ENV.key?("ONLY_ONE_TOKEN")
    end
  end

  down do
    drop_table(:oauth_grants)
  end
end
