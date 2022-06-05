# frozen_string_literal: true

Sequel.migration do
  up do
    extension :date_arithmetic

    # Used by the account verification and close account features
    create_table(:account_statuses) do
      Integer :id, primary_key: true
      String :name, null: false, unique: true
    end
    from(:account_statuses).import(%i[id name], [[1, "Unverified"], [2, "Verified"], [3, "Closed"]])

    create_table(:accounts) do
      primary_key :id, type: Integer
      foreign_key :status_id, :account_statuses, null: false, default: 1
      String :email, null: false
      index :email, unique: true
    end

    # Used by the account expiration feature (OIDC requirement)
    create_table(:account_activity_times) do
      foreign_key :id, :accounts, primary_key: true, type: Integer
      DateTime :last_activity_at, null: false
      DateTime :last_login_at, null: false
      DateTime :expired_at
    end

    # Used by the otp feature
    create_table(:account_otp_keys) do
      foreign_key :id, :accounts, primary_key: true, type: Integer
      String :key, null: false
      Integer :num_failures, null: false, default: 0
      Time :last_use, null: false, default: Sequel::CURRENT_TIMESTAMP
    end

    # Used by the webauthn feature
    create_table(:account_webauthn_user_ids) do
      foreign_key :id, :accounts, primary_key: true, type: Integer
      String :webauthn_id, null: false
    end
    create_table(:account_webauthn_keys) do
      foreign_key :account_id, :accounts, type: Integer
      String :webauthn_id
      String :public_key, null: false
      Integer :sign_count, null: false
      Time :last_use, null: false, default: Sequel::CURRENT_TIMESTAMP
      primary_key %i[account_id webauthn_id]
    end
  end

  down do
    drop_table(:accounts, :account_statuses, :account_activity_times, :account_otp_keys)
  end
end
