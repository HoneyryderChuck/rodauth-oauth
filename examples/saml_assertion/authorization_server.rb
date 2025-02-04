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
  end
  DB.create_table(:oauth_applications) do
    primary_key :id, type: Integer
    # foreign_key :account_id, :accounts, null: false
    String :name, null: false
    String :description, null: true
    String :homepage_url, null: true
    String :redirect_uri, null: false
    String :client_id, null: false, unique: true
    String :client_secret, null: false, unique: true
    String :scopes, null: false
  end
  DB.create_table :oauth_grants do
    primary_key :id, type: Integer
    foreign_key :account_id, :accounts
    foreign_key :oauth_application_id, :oauth_applications, null: false
    String :type, token: true
    String :code, null: true
    String :token, token: true, unique: true
    String :refresh_token, token: true, unique: true
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

# OAuth with myself
CLIENT_ID = ENV.fetch("CLIENT_ID", "CLIENT_ID")

# test application
unless DB[:oauth_applications].where(client_id: CLIENT_ID).first
  DB[:oauth_applications].insert(
    client_id: CLIENT_ID,
    client_secret: BCrypt::Password.create(CLIENT_ID),
    name: "Myself",
    description: "About myself",
    redirect_uri: "http://localhost:9294/callback",
    homepage_url: "http://localhost:9294",
    scopes: "profile.read books.read"
  )
end

class AuthorizationServer < Roda
  plugin :render, views: File.expand_path("../assets/html", __dir__)

  plugin :flash
  plugin :common_logger
  plugin :assets, css: "layout.scss", path: File.expand_path("../assets", __dir__)

  secret = ENV.delete("RODAUTH_SESSION_SECRET") || SecureRandom.random_bytes(64)
  plugin :sessions, secret: secret, key: "authorization-server.session"

  plugin :rodauth, json: true do
    db DB
    enable :oauth_saml_bearer_grant
    title_instance_variable :@page_title

    oauth_application_scopes %w[profile.read books.read books.write]
  end

  plugin :not_found do
    @page_title = "Not Found"
    "Not Found"
  end

  route do |r|
    r.assets
    r.rodauth

    r.root do
      view inline: <<~HTML
        <% if rodauth.logged_in? %>
        <p class="lead">
          You are now logged in to the authorization server. You're able to add client applications, and authorize access to your account.
        </p>
        <% else %>
          <p class="lead">
            This is the demo authorization server for <a href="https://gitlab.com/os85/rodauth-oauth">Rodauth Oauth</a>.
            Rodauth Oauth extends Rodauth to support the OAuth 2.0 authorization protocol, while adhering to the same principles of the parent library.
          </p>
          <p class="lead">In the authorization server, you can setup your account, and also register client applications.</p>
          <p class="text-center">
            <a class="btn btn-outline-primary btn-padded" href="/login">Login</a>
            <a class="btn btn-outline-secondary btn-padded" href="/create-account">Sign Up</a>
          </p>
          <footer class="lead">This demo site is part of the Rodauth repository, so if you want to know how it works, you can <a href="https://gitlab.com/os85/rodauth-oauth/tree/master/examples">review the source</a>.</footer>
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
  require "rackup"

  Rackup::Server.start(
    app: AuthorizationServer, Port: 9292
  )
end
