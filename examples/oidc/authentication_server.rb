# frozen_string_literal: true

require "roda"
require "sequel/core"
require "securerandom"
require "net/http"
require "bcrypt"
require "digest/sha1"
require "jwt"

if (url = ENV.delete("DATABASE_URL"))
  DB = Sequel.connect(url)
else
  DB = Sequel.sqlite
  DB.create_table(:accounts) do
    primary_key :id, type: :Bignum
    String :email, null: false
    index :email, unique: true
    String :name
    String :ph, null: false
  end
  # Used by the account expiration feature
  DB.create_table(:account_activity_times) do
    foreign_key :id, :accounts, primary_key: true, type: :Bignum
    DateTime :last_activity_at, null: false
    DateTime :last_login_at, null: false
    DateTime :expired_at
  end
  DB.create_table(:oauth_applications) do
    primary_key :id, type: Integer
    foreign_key :account_id, :accounts, null: true
    String :name, null: false
    String :description, null: true
    String :homepage_url, null: true
    String :redirect_uri, null: false
    String :client_id, null: false, unique: true
    String :client_secret, null: false, unique: true
    String :registration_access_token, null: true
    String :initiate_login_uri, null: true
    String :scopes, null: false
    # extra params
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
    # oidc extra params
    String :sector_identifier_uri, null: true
    String :application_type, null: true
    String :subject_type, null: true
    String :id_token_signed_response_alg, null: true
    String :id_token_encrypted_response_alg, null: true
    String :id_token_encrypted_response_enc, null: true
    String :userinfo_signed_response_alg, null: true
    String :userinfo_encrypted_response_alg, null: true
    String :userinfo_encrypted_response_enc, null: true
    String :request_object_signing_alg, null: true
    String :request_object_encryption_alg, null: true
    String :request_object_encryption_enc, null: true
    String :request_uris, null: true

    # JWT/OIDC per application signing verification
    String :jwt_public_key, type: :text
    # RP-initiated logout
    String :post_logout_redirect_uris
  end
  DB.create_table :oauth_grants do
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
    String :code_challenge
    String :code_challenge_method
    String :nonce
    String :acr
    String :claims_locales
    String :claims
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

# OAuth with myself
CLIENT_ID = ENV.fetch("CLIENT_ID", "CLIENT_ID")
hash = BCrypt::Password.create("password", cost: BCrypt::Engine::MIN_COST)

# test user
DB[:accounts].insert_conflict(target: :email).insert(name: "Fernando Pessoa", email: "foo@bar.com", ph: hash)

TEST_ADDRESS = {
  country: "DE",
  street_address: "Heiligengeistbrücke 13",
  formatted: "Heiligengeistbrücke 13\nOhrenbach\nFreistaat Bayern\n91620\nDE",
  locality: "Ohrenbach",
  postal_code: "91620",
  region: "Freistaat Bayern"
}.freeze

TEST_PROFILE = {
  name: "Ferdinand Mensch",
  family_name: "Gottschalk",
  given_name: "Peter",
  middle_name: "Franz",
  nickname: "Poltermeister",
  preferred_username: "PM",
  profile: "https://id-provider/franz",
  picture: "https://id-provider/franz.jpg",
  website: "https://id-provider/franz/about",
  birthdate: "1996-08-30",
  gender: "male",
  zoneinfo: "Europe/Paris",
  locale: "de-DE",
  updated_at: Time.new(2022, 9, 10, 14, 1).to_i
}.freeze

# test application
unless DB[:oauth_applications].where(client_id: CLIENT_ID).first
  email = "admin@localhost.com"
  account_id = DB[:accounts].where(email: email).get(:id) || begin
    DB[:accounts].insert(email: email, ph: hash)
  end

  application_id = DB[:oauth_applications].insert(
    client_id: CLIENT_ID,
    client_secret: BCrypt::Password.create(CLIENT_ID),
    name: "Myself",
    description: "About myself",
    redirect_uri: "http://localhost:9293/auth/openid_connect/callback",
    homepage_url: "http://localhost:9293",
    scopes: "openid email address phone profile books.read",
    account_id: account_id
  )
  DB[:oauth_applications].where(id: application_id).first
end

# rubocop:disable Style/MutableConstant
# PRIV_KEY = OpenSSL::PKey::EC.new(File.read(File.join(__dir__, "..", "ecprivkey.pem")))
PRIV_KEYS = [OpenSSL::PKey::RSA.new(File.read(File.join(__dir__, "rsaprivkey.pem")))]
# PUB_KEY = OpenSSL::PKey::EC.new(File.read(File.join(__dir__, "..", "ecpubkey.pem")))
PUB_KEYS = [OpenSSL::PKey::RSA.new(File.read(File.join(__dir__, "rsapubkey.pem")))]
# rubocop:enable Style/MutableConstant

class AuthenticationServer < Roda
  plugin :render, views: File.expand_path("../assets/html", __dir__)

  plugin :flash
  plugin :common_logger
  plugin :assets, css: "layout.scss", path: File.expand_path("../assets", __dir__)

  secret = ENV.delete("RODAUTH_SESSION_SECRET") || SecureRandom.random_bytes(64)
  plugin :sessions, secret: secret, key: "authorization-server.session"

  plugin :rodauth, json: true do
    db DB
    enable :login, :logout, :create_account, :oidc, :oidc_session_management,
           :oauth_client_credentials_grant, :oauth_pkce, :oauth_token_introspection,
           :oidc_dynamic_client_registration, :oauth_jwt_bearer_grant, :oauth_jwt_secured_authorization_request,
           :oidc_rp_initiated_logout

    login_return_to_requested_location? true
    account_password_hash_column :ph
    title_instance_variable :@page_title
    login_return_to_requested_location? true

    oauth_application_scopes %w[openid email address phone profile books.read]
    oauth_valid_uri_schemes %w[http https]

    oauth_jwt_keys("RS256" => PRIV_KEYS)
    oauth_jwt_public_keys("RS256" => PUB_KEYS)

    oauth_require_pkce false
    oauth_response_mode "query"

    oidc_authorize_on_prompt_none? { |_account| true }
    oauth_request_object_signing_alg_allow_none true
    oauth_jwt_jws_algorithms_supported { super() | %w[none] }
    oauth_acr_values_supported { super() | %w[1 2] }

    before_register do
      # bypass authentication
    end

    get_oidc_param do |account, param|
      case param
      when :email
        account[:email]
      when :email_verified, :phone_number_verified
        true
      when :phone_number
        "804-222-1111"
      when :street_address, :locality, :region, :postal_code, :country
        TEST_ADDRESS[param]
      when :name, :family_name, :given_name, :middle_name, :nickname,
           :preferred_username, :profile, :picture, :website, :gender,
           :birthdate, :zoneinfo, :locale, :updated_at
        TEST_PROFILE[param]
      end
    end
  end

  plugin :not_found do
    @page_title = "Not Found"
    "Not Found"
  end

  route do |r|
    r.assets
    r.rodauth
    rodauth.load_registration_client_uri_routes
    rodauth.load_openid_configuration_route
    rodauth.load_webfinger_route

    r.root do
      view inline: <<~HTML
        <% if rodauth.logged_in? %>
        <p class="lead">
          You are now logged in to the OpenID authentication server. You're able to add client applications, and authenticate with your account.
        </p>
        <% else %>
          <p class="lead">
            This is the demo authentication server for <a href="https://gitlab.com/os85/rodauth-oauth">Roda Oauth - Open ID Connect</a>.
            Roda Oauth extends Rodauth to support the OAuth 2.0 authorization protocol, while adhering to the same principles of the parent library.
          </p>
          <p class="lead">In the authentication server, you can setup your account, and also register client applications.</p>
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

    r.on "rotate-keys" do
      r.get do
        jws_key = OpenSSL::PKey::RSA.generate(2048)
        jws_public_key = jws_key.public_key

        PRIV_KEYS.unshift(jws_key)
        PUB_KEYS.unshift(jws_public_key)

        "rotated"
      end
    end
  end
  freeze
end

DB.freeze

if $PROGRAM_NAME == __FILE__
  require "rack"

  Rack::Server.start(
    app: AuthenticationServer,
    pid: ENV["PIDFILE"],
    Port: ENV.fetch("PORT", 9292)
  )
end
