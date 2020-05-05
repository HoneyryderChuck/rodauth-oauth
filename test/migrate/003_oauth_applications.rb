Sequel.migration do
  up do
    # Used by the account verification and close account features
    create_table(:oauth_applications) do
      Integer :id, :primary_key=>true
      String :name, :null=>false
      String :description, :null=>false
      String :homepage_url, :null=>false
      String :callback_url, :null=>false
      String :client_id, :null=>false, :unique => true
      String :client_secret, :null=>false, :unique => true
      String :scopes, :null => false
    end

  end

  down do
    drop_table(:oauth_applications)
  end
end