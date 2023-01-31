# frozen_string_literal: true

Sequel.migration do
  up do
    create_table :oauth_grants do |_t|
      primary_key :id, type: Integer
      foreign_key :account_id, :accounts # , null: false unless client credentials, or device code grant
      foreign_key :oauth_application_id, :oauth_applications, null: false
      String :type, null: true

      String :code, null: true
      index %i[oauth_application_id code], unique: true
      String :token, token: true, unique: true
      # hashed tokens
      String :token_hash, token: true, unique: true
      String :refresh_token, token: true, unique: true
      # hashed tokens
      String :refresh_token_hash, token: true, unique: true
      Time :expires_in, null: false

      String :redirect_uri
      Time :revoked_at
      String :scopes, null: false
      index %i[oauth_application_id account_id scopes], unique: true if ENV.key?("ONLY_ONE_TOKEN")
      # if using access_types
      String :access_type, null: false, default: "offline"
      # if using PKCE flow
      String :code_challenge
      String :code_challenge_method
      # device code grant
      String :user_code, null: true, unique: true
      Time :last_polled_at
      # :oauth_tls_client_auth
      String :certificate_thumbprint
      # resource indicators
      String :resource
      # oidc
      String :nonce
      String :acr
      String :claims_locales
      String :claims
    end
  end

  down do
    drop_table(:oauth_grants)
  end
end
