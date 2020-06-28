# frozen_string_literal: true

require "roda"
require "sequel/core"
require "securerandom"
require "net/http"
require "bcrypt"
require "digest/sha1"
require "jwt"
# require "json/jwt"

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
    String :description, null: false
    String :homepage_url, null: false
    String :redirect_uri, null: false
    String :client_id, null: false, unique: true
    String :client_secret, null: false, unique: true
    String :scopes, null: false
  end
  DB.create_table :oauth_grants do |_t|
    primary_key :id, type: Integer
    foreign_key :account_id, :accounts, null: false
    foreign_key :oauth_application_id, :oauth_applications, null: false
    String :code, null: false
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
  DB.create_table :oauth_tokens do |_t|
    primary_key :id, type: Integer
    foreign_key :account_id, :accounts
    foreign_key :oauth_grant_id, :oauth_grants
    foreign_key :oauth_token_id, :oauth_tokens
    foreign_key :oauth_application_id, :oauth_applications, null: false
    String :refresh_token, token: true
    DateTime :expires_in, null: false
    DateTime :revoked_at
    String :scopes, null: false
  end
end

if ENV.delete("RODAUTH_DEBUG")
  require "logger"
  DB.loggers << Logger.new($stdout)
end

DB.extension :date_arithmetic
DB.freeze

# OAuth with myself
CLIENT_ID = ENV.fetch("CLIENT_ID", "CLIENT_ID")
hash = ::BCrypt::Password.create("password", cost: BCrypt::Engine::MIN_COST)

# test user
DB[:accounts].insert_conflict(target: :email).insert(email: "foo@bar.com", ph: hash)

# test application
TEST_APPLICATION = DB[:oauth_applications].where(client_id: CLIENT_ID).first || begin
  email = "admin@localhost.com"
  account_id = DB[:accounts].where(email: email).get(:id) || begin
    DB[:accounts].insert(email: email, ph: hash)
  end

  application_id = DB[:oauth_applications].insert(
    client_id: CLIENT_ID,
    client_secret: BCrypt::Password.create(CLIENT_ID),
    name: "Myself",
    description: "About myself",
    redirect_uri: "http://localhost:9293/callback",
    homepage_url: "http://localhost:9293",
    scopes: "profile.read books.read",
    account_id: account_id
  )
  DB[:oauth_applications].where(id: application_id).first
end

# PRIV_KEY = OpenSSL::PKey::EC.new(File.read(File.join(__dir__, "..", "ecprivkey.pem")))
PRIV_KEY = OpenSSL::PKey::RSA.new(File.read(File.join(__dir__, "..", "rsaprivkey.pem")))
# PUB_KEY = OpenSSL::PKey::EC.new(File.read(File.join(__dir__, "..", "ecpubkey.pem")))
PUB_KEY = OpenSSL::PKey::RSA.new(File.read(File.join(__dir__, "..", "rsapubkey.pem")))

class AuthorizationServer < Roda
  plugin :render, layout: { inline: <<~LAYOUT }
    <!DOCTYPE html>
    <html>
    <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css"
          rel="stylesheet"
          integrity="sha384-Vkoo8x4CGsO3+Hhxv8T/Q5PaXtkKtu6ug5TOeNV6gBiFeWPGFN9MuhOf23Q9Ifjh"
          crossorigin="anonymous"></link>
    <title>Roda Oauth Demo - <%= @page_title %></title>
    <style>
    .error {border: 1px #a00 solid;
    span.error_message {
      color: #a00;
      background-color: #ffffe0;
      border-color: 1px solid #eeeed0;
      padding: 5px 2px;
      display: inline-block; 
    }
    span.error_message:before {
        content: "(!) "
    }
    input.rodauth_hidden {
      display: none;
    }
    </style>
    </head>
    <body>
    <nav class="navbar navbar-default" role="navigation">
      <div class="container">
        <a class="navbar-brand" href="/">Roda Oauth Demo - Authorization Server</a>
          <% if rodauth.logged_in? %>
            <ul class="navbar-nav mr-auto">
              <li class="nav-item">
                <a class="nav-link" href="oauth-applications">Client Applications</a>
              </li>
            </ul>
            <ul class="navbar-nav ml-auto nav-flex-icons">
              <li>
                <%= DB[:accounts].where(:id=>rodauth.session_value).get(:email) %>
              </li>
              <li class="nav-item">
                <form action="/logout" class="navbar-form pull-right" method="post">
                  <%= csrf_tag("/logout") %>
                  <input class="btn btn-primary form-control auth-button" type="submit" value="Logout" />
                </form>
              </li>
            </ul>
          <% end %>
        </div>
      </div>
    </nav>
    <div class="container">
      <% if flash['notice'] %>
        <div class="alert alert-success"><p><%= flash['notice'] %></p></div>
      <% end %>
      <% if flash['error'] %>
        <div class="alert alert-danger"><p><%= flash['error'] %></p></div>
      <% end %>
      <h1><%= @page_title %></h1>
    
      <%= yield %>
    </div>
    </body>
    </html>
  LAYOUT

  plugin :flash
  plugin :common_logger

  secret = ENV.delete("RODAUTH_SESSION_SECRET") || SecureRandom.random_bytes(64)
  plugin :sessions, secret: secret, key: "authorization-server.session"

  plugin :rodauth, json: true do
    db DB
    enable :login, :logout, :create_account, :oauth_jwt
    login_return_to_requested_location? true
    account_password_hash_column :ph
    title_instance_variable :@page_title
    login_return_to_requested_location? true
    oauth_application_scopes %w[profile.read books.read books.write]
    oauth_application_default_scope %w[profile.read]
    oauth_jwt_key PRIV_KEY
    oauth_jwt_public_key PUB_KEY
    #     oauth_jwt_algorithm "ES256"
    oauth_jwt_algorithm "RS256"
    oauth_tokens_refresh_token_hash_column :refresh_token
  end

  plugin :not_found do
    @page_title = "Not Found"
    "Not Found"
  end

  route do |r|
    r.rodauth
    rodauth.oauth_applications
    rodauth.oauth_server_metadata

    r.root do
      @application = TEST_APPLICATION
      view inline: <<~HTML
        <% if rodauth.logged_in? %>
         <p>Now you can <a href="/oauth-applications">create oauth applications</a>
        <% else %>
          <p>
            This is the demo authorization server for <a href="https://gitlab.com/honeyryderchuck/roda-oauth">Roda Oauth</a>.
            Roda Oauth extends Rodauth to support the OAuth 2.0 authorization protocol, while adhering to the same principles of the parent library.
          </p>
          <p>In the authorization server, you can setup your account, and also register client applications.</p>
        
          <a class="btn btn-primary btn-lg" href="/login">Login</a>
          <a class="btn btn-info btn-lg" href="/create-account">Sign Up</a>
        
          <footer>This demo site is part of the Rodauth repository, so if you want to know how it works, you can <a href="https://gitlab.com/honeyryderchuck/roda-oauth/tree/master/examples/roda">review the source</a>.</footer>
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

if $PROGRAM_NAME == __FILE__
  require "rack"
  require "rack/cors"

  app = Rack::Builder.app do
    use Rack::Cors, debug: true, logger: Logger.new(STDOUT) do
      allow do
        origins "*"

        resource "*",
                 headers: :any,
                 methods: %i[get post]
      end
    end
    run AuthorizationServer
  end

  Rack::Server.start(
    app: app, Port: 9292
  )
end
