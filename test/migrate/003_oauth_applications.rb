# frozen_string_literal: true

Sequel.migration do
  up do
    # Used by the account verification and close account features
    create_table(:oauth_applications) do
      primary_key :id, type: Integer
      foreign_key :account_id, :accounts, null: true
      String :name, null: false
      String :description, null: true
      String :homepage_url, null: false
      String :redirect_uri, null: false
      String :client_id, null: false, unique: true
      String :client_secret, null: false, unique: true
      String :scopes, null: false
      # extra params
      String :token_endpoint_auth_method, null: true
      String :grant_types, null: true
      String :response_types, null: true
      String :client_uri, null: true
      String :logo_uri, null: true
      String :tos_uri, null: true
      String :policy_uri, null: true
      String :jwks_uri, null: true
      String :jwks, null: true, type: :text
      String :contacts, null: true
      String :software_id, null: true
      String :software_version, null: true
      # JWT/OIDC per application signing verification
      String :jwt_public_key, type: :text
      # RP-initiated logout
      String :post_logout_redirect_uri
    end
  end

  down do
    drop_table(:oauth_applications)
  end
end
