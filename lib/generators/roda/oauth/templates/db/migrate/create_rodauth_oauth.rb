class CreateRodauthOAuth < ActiveRecord::Migration<%= migration_version %>
  def change
    create_table :oauth_applications do |t|
      t.foreign_key :accounts, column: :id
      t.string :name, null: false
      t.string :description, null: false
      t.string :homepage_url, null: false
      t.string :redirect_uri, null: false
      t.string :client_id, null: false, index: { unique: true }
      t.string :client_secret, null: false, index: { unique: true }
      t.string :scopes, null: false
      t.datetime :created_at, null: false, default: -> { "CURRENT_TIMESTAMP" }
    end

    create_table :oauth_grants do |t|
      t.foreign_key :accounts, column: :id
      t.foreign_key :oauth_applications, column: :id
      t.tring :code, null: false
      t.datetime :expires_in, null: false
      t.string :redirect_uri
      t.datetime :revoked_at
      t.string :scopes, null: false
      t.datetime :created_at, null: false, default: -> { "CURRENT_TIMESTAMP" }
      t.index(%i[oauth_application_id code], unique: true)
    end

    create_table :oauth_tokens do |t|
      t.foreign_key :oauth_grants, column: :id
      t.foreign_key :oauth_tokens, column: :id
      t.foreign_key :oauth_applications, column: :id, null: false
      t.string :token, null: false, token: true
      t.string :refresh_token
      t.datetime :expires_in, null: false
      t.datetime :revoked_at
      t.string :scopes, null: false
      t.datetime :created_at, null: false, default: -> { "CURRENT_TIMESTAMP" }
    end
  end
end