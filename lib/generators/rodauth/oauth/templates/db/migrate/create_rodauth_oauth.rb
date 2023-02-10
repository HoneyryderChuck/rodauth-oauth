class CreateRodauthOauth < ActiveRecord::Migration<%= migration_version %>
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
      t.string :client_registration_token, null: true
      t.string :scopes, null: false
      t.datetime :created_at, null: false, default: -> { "CURRENT_TIMESTAMP" }

      # :oauth_dynamic_client_configuration enabled, extra optional params
      t.string :token_endpoint_auth_method, null: true
      t.string :grant_types, null: true
      t.string :response_types, null: true
      t.string :client_uri, null: true
      t.string :logo_uri, null: true
      t.string :tos_uri, null: true
      t.string :policy_uri, null: true
      t.string :jwks_uri, null: true
      t.string :jwks, null: true
      t.string :contacts, null: true
      t.string :software_id, null: true
      t.string :software_version, null: true

      # :oidc_dynamic_client_configuration enabled, extra optional params
      t.string :sector_identifier_uri, null: true
      t.string :application_type, null: true
      t.string :initiate_login_uri, null: true

      # :oidc enabled
      t.string :subject_type, null: true
      t.string :id_token_signed_response_alg, null: true
      t.string :id_token_encrypted_response_alg, null: true
      t.string :id_token_encrypted_response_enc, null: true
      t.string :userinfo_signed_response_alg, null: true
      t.string :userinfo_encrypted_response_alg, null: true
      t.string :userinfo_encrypted_response_enc, null: true

      # :oauth_jwt_secured_authorization_request
      t.string :request_object_signing_alg, null: true
      t.string :request_object_encryption_alg, null: true
      t.string :request_object_encryption_enc, null: true
      t.string :request_uris, null: true
      t.boolean :require_pushed_authorization_requests, null: false, default: false

      # :oidc_rp_initiated_logout enabled
      t.string :post_logout_redirect_uris, null: false
    end

    create_table :oauth_grants do |t|
      t.integer :account_id
      t.foreign_key :accounts, column: :account_id
      t.integer :oauth_application_id
      t.foreign_key :oauth_applications, column: :oauth_application_id
      t.string :type, null: true
      t.string :code, null: true
      t.index(%i[oauth_application_id code], unique: true)
      t.string :token, unique: true
      t.string :refresh_token, unique: true
      t.datetime :expires_in, null: false
      t.string :redirect_uri
      t.datetime :revoked_at
      t.string :scopes, null: false
      t.datetime :created_at, null: false, default: -> { "CURRENT_TIMESTAMP" }
      t.string :access_type, null: false, default: "offline"

      # :oauth_pkce enabled
      t.string :code_challenge
      t.string :code_challenge_method

      # :oauth_device_code_grant enabled
      t.string :user_code, null: true, unique: true
      t.datetime :last_polled_at, null: true

      # :resource_indicators enabled
      t.string :resource

      # :oidc enabled
      t.string :nonce
      t.string :acr
      t.string :claims_locales
      t.string :claims
    end

    create_table :oauth_pushed_requests do |t|
      t.integer :oauth_application_id
      t.foreign_key :oauth_applications, column: :oauth_application_id
      t.string :params, null: false
      t.datetime :expires_in, null: false
      t.index %i[oauth_application_id code], unique: true
    end
  end
end