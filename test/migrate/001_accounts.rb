Sequel.migration do
  up do
  	extension :date_arithmetic

    # Used by the account verification and close account features
    create_table(:account_statuses) do
      Integer :id, :primary_key=>true
      String :name, :null=>false, :unique=>true
    end
    from(:account_statuses).import([:id, :name], [[1, 'Unverified'], [2, 'Verified'], [3, 'Closed']])


  	create_table(:accounts) do
      primary_key :id, :type=>:Bignum
      foreign_key :status_id, :account_statuses, :null=>false, :default=>1
      String :email, :null=>false
      index :email, :unique=>true
    end

  end

  down do
    drop_table(:accounts, :account_statuses)
  end
end