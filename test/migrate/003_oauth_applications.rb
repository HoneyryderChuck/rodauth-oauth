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
      String :jws_jwk
    end
  end

  down do
    drop_table(:oauth_applications)
  end
end
