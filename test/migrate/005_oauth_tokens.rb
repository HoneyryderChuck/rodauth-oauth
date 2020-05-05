Sequel.migration do
  up do
    create_table :oauth_tokens do |t|
      Integer :id, :primary_key=>true
      foreign_key :oauth_grant_id, :oauth_grants
      foreign_key :oauth_token_id, :oauth_tokens
      foreign_key :oauth_application_id, :oauth_applications, :null=>false
      String :token, :null=>false, token: true
      String :refresh_token
      DateTime :expires_in, :null=>false
      DateTime :revoked_at
      String :scopes, :null => false
    end
  end

  down do
    drop_table(:oauth_grants)
  end
end