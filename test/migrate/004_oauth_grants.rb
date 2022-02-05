# frozen_string_literal: true

Sequel.migration do
  up do
    create_table :oauth_grants do |_t|
      primary_key :id, type: Integer
      foreign_key :account_id, :accounts # , null: false unless device code grant
      foreign_key :oauth_application_id, :oauth_applications, null: false
      String :code, null: false
      index %i[oauth_application_id code], unique: true
      Time :expires_in, null: false
      String :redirect_uri
      Time :revoked_at
      String :scopes, null: false
      # if using access_types
      String :access_type, null: false, default: "offline"
      # if using PKCE flow
      String :code_challenge
      String :code_challenge_method
      String :nonce
      # device code grant: user code
      String :user_code, null: true, unique: true
      Integer :attempts, null: true
    end
  end

  down do
    drop_table(:oauth_grants)
  end
end
