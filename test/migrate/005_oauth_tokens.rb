# frozen_string_literal: true

Sequel.migration do
  up do
    create_table :oauth_tokens do |_t|
      primary_key :id, type: Integer
      foreign_key :account_id, :accounts
      foreign_key :oauth_grant_id, :oauth_grants
      foreign_key :oauth_token_id, :oauth_tokens
      foreign_key :oauth_application_id, :oauth_applications, null: false
      String :token, token: true
      String :token_hash, token: true
      String :refresh_token, token: true
      String :refresh_token_hash, token: true
      DateTime :expires_in, null: false
      DateTime :revoked_at
      String :scopes, null: false
    end
  end

  down do
    drop_table(:oauth_grants)
  end
end
