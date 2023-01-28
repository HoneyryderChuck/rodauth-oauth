# frozen_string_literal: true

Sequel.migration do
  up do
    create_table :oauth_pushed_requests do |_t|
      foreign_key :oauth_application_id, :oauth_applications, null: false
      String :code, null: false, unique: true
      String :params, null: false
      Time :expires_in, null: false
      index %i[oauth_application_id code], unique: true
    end
  end

  down do
    drop_table(:oauth_pushed_requests)
  end
end
