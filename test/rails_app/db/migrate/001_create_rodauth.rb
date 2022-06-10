# frozen_string_literal: true

version = eval("#{::ActiveRecord::VERSION::MAJOR}.#{::ActiveRecord::VERSION::MINOR}")

superclass = if ActiveRecord.version >= Gem::Version.new("5.0.0")
               ActiveRecord::Migration[version]
             else
               ActiveRecord::Migration
             end

class CreateRodauth < superclass
  self.verbose = false

  def change
    unless table_exists?(:account_statuses)
      create_table :account_statuses do |t|
        t.string :name, null: false, index: { unique: true }
      end
      execute <<-SQL
  INSERT INTO account_statuses (id, name) values
  (1, 'Unverified'),
  (2, 'Verified'),
  (3, 'Closed')
      SQL
    end


    create_table :accounts do |t|
      t.string :email, null: false, index: { unique: true }
      t.string :ph
      t.integer :status_id, references: :account_statuses, null: false, default: 1
    end unless table_exists?(:accounts)

    # Used by the account expiration feature (OIDC requirement)
    create_table(:account_activity_times) do
      t.foreign_key :accounts, column: :id
      t.datetime :last_activity_at, null: false
      t.datetime :last_login_at, null: false
      t.datetime :expired_at
    end unless table_exists?(:account_activity_times)

    # Used by the otp feature
    create_table(:account_otp_keys) do
      t.foreign_key :accounts, column: :id
      t.string :key, null: false
      t.integer :num_failures, null: false, default: 0
      t.datetime :last_use, null: false, default: ->{ Time.now }
    end unless table_exists?(:account_otp_keys)

    # Used by the webauthn feature
    create_table(:account_webauthn_user_ids) do
      t.foreign_key :accounts, column: :id
      t.string :webauthn_id, null: false
    end unless table_exists?(:account_webauthn_user_ids)

    create_table(:account_webauthn_keys) do
      t.references :account, foreign_key: true
      t.string :webauthn_id
      t.string :public_key, null: false
      t.integer :sign_count, null: false
      t.datetime :last_use, null: false, default: ->{ Time.now }
    end unless table_exists?(:account_webauthn_keys)
  end
end
