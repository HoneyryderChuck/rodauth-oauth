# frozen_string_literal: true

require "roda"
require "sequel/core"
require "securerandom"
require "net/http"
require "bcrypt"
require "digest/sha1"

if (url = ENV.delete("DATABASE_URL"))
  DB = Sequel.connect(url)
else
  DB = Sequel.sqlite
  DB.create_table(:accounts) do
    primary_key :id, type: :Bignum
    String :email, null: false
    index :email, unique: true
    String :ph, null: false
  end
  DB.create_table(:oauth_applications) do
    primary_key :id, type: Integer
    foreign_key :account_id, :accounts, null: false
    String :name, null: false
    String :description, null: true
    String :homepage_url, null: false
    String :redirect_uri, null: false
    String :client_id, null: false, unique: true
    String :client_secret, null: false, unique: true
    String :scopes, null: false

    String :token_endpoint_auth_method, null: true
    String :grant_types, null: true
    String :response_types, null: true
    String :client_uri, null: true
    String :logo_uri, null: true
    String :tos_uri, null: true
    String :policy_uri, null: true
    String :jwks_uri, null: true
    String :jwks, null: true, type: :text
    String :contacts, null: true
    String :software_id, null: true
    String :software_version, null: true
  end
  DB.create_table :oauth_grants do |_t|
    primary_key :id, type: Integer
    foreign_key :account_id, :accounts, null: false
    foreign_key :oauth_application_id, :oauth_applications, null: false
    String :type, null: false
    String :code, null: true
    String :token, token: true, unique: true
    String :refresh_token, token: true, unique: true
    DateTime :expires_in, null: false
    String :redirect_uri
    DateTime :revoked_at
    String :scopes, null: false
    index %i[oauth_application_id code], unique: true
    String :access_type, null: false, default: "offline"
    # if using PKCE flow
    # String :code_challenge
    # String :code_challenge_method
  end
end

if ENV.delete("RODAUTH_DEBUG")
  require "logger"
  DB.loggers << Logger.new($stdout)
end

DB.extension :date_arithmetic

hash = ::BCrypt::Password.create("password", cost: BCrypt::Engine::MIN_COST)
# test user
DB[:accounts].insert_conflict(target: :email).insert(email: "foo@bar.com", ph: hash)

ADMIN_ACCOUNT = DB[:accounts].insert_conflict(target: :email).insert(email: "admin@localhost.com", ph: hash)

class AuthorizationServer < Roda
  plugin :render, views: File.expand_path("../assets/html", __dir__)

  plugin :flash
  plugin :common_logger
  plugin :assets, css: "layout.scss", path: File.expand_path("../assets", __dir__)

  secret = ENV.delete("RODAUTH_SESSION_SECRET") || SecureRandom.random_bytes(64)
  plugin :sessions, secret: secret, key: "authorization-server.session"

  plugin :rodauth, json: true do
    db DB
    enable :login, :logout, :create_account, :oauth, :oauth_dynamic_client_registration
    login_return_to_requested_location? true
    account_password_hash_column :ph
    title_instance_variable :@page_title

    oauth_application_scopes %w[profile.read books.read books.write]
    oauth_valid_uri_schemes %w[http https]

    oauth_grants_refresh_token_hash_column :refresh_token

    before_register do
      email = request.env["HTTP_AUTHORIZATION"]
      authorization_required unless email
      account = _account_from_login(email)
      authorization_required unless account
      @oauth_application_params[:account_id] = account[:id]
    end
  end

  plugin :not_found do
    @page_title = "Not Found"
    "Not Found"
  end

  route do |r|
    r.assets
    r.rodauth
    rodauth.load_oauth_application_management_routes
    rodauth.load_oauth_grant_management_routes
    rodauth.load_oauth_server_metadata_route

    r.root do
      view inline: <<~HTML
        <% if rodauth.logged_in? %>
        <p class="lead">
          You are now logged in to the authorization server. You're able to add client applications, and authorize access to your account.
        </p>
        <% else %>
          <p class="lead">
            This is the demo authorization server for <a href="https://gitlab.com/honeyryderchuck/rodauth-oauth">Roda Oauth</a>.
            Roda Oauth extends Rodauth to support the OAuth 2.0 authorization protocol, while adhering to the same principles of the parent library.
          </p>
          <p class="lead">In the authorization server, you can setup your account, and also register client applications.</p>
          <p class="text-center">
            <a class="btn btn-outline-primary btn-padded" href="/login">Login</a>
            <a class="btn btn-outline-secondary btn-padded" href="/create-account">Sign Up</a>
          </p>
          <footer class="lead">This demo site is part of the Rodauth repository, so if you want to know how it works, you can <a href="https://gitlab.com/honeyryderchuck/rodauth-oauth/tree/master/examples">review the source</a>.</footer>
        <% end %>
      HTML
    end

    r.on "books" do
      rodauth.require_oauth_authorization("books.read")
      r.get do
        [
          { "name" => "Anna Karenina", "author" => "Leo Tolstoy" },
          { "name" => "Madame Bovary", "author" => "Gustave Flaubert" },
          { "name" => "War and Peace", "author" => "Leo Tolstoy" },
          { "name" => "The Adventures of Huckleberry Finn", "author" => "Mark Twain" },
          { "name" => "The stories", "author" => "Anton Chekhov" },
          { "name" => "Middlemarch", "author" => "George Eliot" },
          { "name" => "Moby-Dick", "author" => "Herman Melville" },
          { "name" => "Great Expectations", "author" => "Charles Dickens" },
          { "name" => "Crime and Punishment", "author" => "Fyodor Dostoevsky" },
          { "name" => "Emma", "author" => "Jane Austen" }
        ]
      end
    end
  end
  freeze
end

DB.freeze

if $PROGRAM_NAME == __FILE__
  require "rack"

  Rack::Server.start(
    app: AuthorizationServer, Port: 9292
  )
end
