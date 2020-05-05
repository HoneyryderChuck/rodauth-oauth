Sequel.migration do
  up do
    create_table :oauth_grants do |t|
      Integer :id, :primary_key=>true
      foreign_key :account_id, :accounts, :null=>false
      foreign_key :oauth_application_id, :oauth_applications, :null=>false
      String :code, :null=>false, :unique=>true
      DateTime :expires_in, :null=>false
      String :grants, :null => false
    end
  end

  down do
    drop_table(:oauth_grants)
  end
end