# frozen_string_literal: true

Sequel.migration do
  up do
    create_table :oauth_dpop_proofs do |_t|
      String :jti, primary_key: true, null: false
      Time :first_use, null: false, default: Sequel::CURRENT_TIMESTAMP
    end
  end

  down do
    drop_table(:oauth_dpop_proofs)
  end
end
