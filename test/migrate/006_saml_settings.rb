# frozen_string_literal: true

Sequel.migration do
  up do
    create_table :oauth_saml_settings do |_t|
      primary_key :id, type: Integer
      foreign_key :oauth_application_id, :oauth_applications, null: false, unique: true
      String :idp_cert, null: true, type: :text
      String :idp_cert_fingerprint, null: true
      String :idp_cert_fingerprint_algorithm, null: true
      TrueClass :check_idp_cert_expiration, null: true
      String :name_identifier_format, null: true, type: :text
      String :audience, null: true
      String :issuer, null: false, unique: true
    end
  end

  down do
    drop_table(:oauth_saml_settings)
  end
end
