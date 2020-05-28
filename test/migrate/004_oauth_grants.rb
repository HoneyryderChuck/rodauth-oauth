# frozen_string_literal: true

Sequel.migration do
  up do
    create_table :oauth_grants do |_t|
      Integer :id, primary_key: true
      foreign_key :account_id, :accounts, null: false
      foreign_key :oauth_application_id, :oauth_applications, null: false
      String :code, null: false
      DateTime :expires_in, null: false
      String :redirect_uri
      DateTime :revoked_at
      String :scopes, null: false
      index %i[oauth_application_id code], unique: true
      # if using access_types
      String :access_type, null: false, default: "offline"
      # if using PKCE flow
      String :code_challenge
      String :code_challenge_method
    end
  end

  down do
    drop_table(:oauth_grants)
  end
end
