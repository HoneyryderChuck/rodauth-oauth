# frozen_string_literal: true

Sequel.migration do
  up do
    # Used by the account verification and close account features
    create_table(:oauth_applications) do
      primary_key :id, type: Integer
      foreign_key :account_id, :accounts, null: false
      String :name, null: false
      String :description, null: false
      String :homepage_url, null: false
      String :redirect_uri, null: false
      String :client_id, null: false, unique: true
      String :client_secret, null: false, unique: true
      String :scopes, null: false
      # JWT/OIDC per application signing verification
      String :jwt_public_key, type: :text
      String :jws_jwk, type: :text
      # RP-initiated logout
      String :post_logout_redirect_uri
    end
  end

  down do
    drop_table(:oauth_applications)
  end
end
