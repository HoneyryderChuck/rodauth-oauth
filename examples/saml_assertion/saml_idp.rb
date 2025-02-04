# frozen_string_literal: true

require "roda"
require "sequel/core"
require "securerandom"
require "bcrypt"
require "saml_idp"
require "onelogin/ruby-saml"

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
end

if ENV.delete("RODAUTH_DEBUG")
  require "logger"
  DB.loggers << Logger.new($stdout)
end

hash = BCrypt::Password.create("password", cost: BCrypt::Engine::MIN_COST)
# test user
DB[:accounts].insert_conflict(target: :email).insert(email: "foo@bar.com", ph: hash)

AUTHORIZATION_SERVER = ENV.fetch("AUTHORIZATION_SERVER_URI", "http://localhost:9292")

SamlIdp.configure do |config|
  service_providers = {
    "http://localhost:9293" => {
      fingerprint: SamlIdp::Default::FINGERPRINT,
      metadata_url: "http://localhost:9293/saml/metadata",

      # We now validate AssertionConsumerServiceURL will match the MetadataURL set above.
      # *If* it's not going to match your Metadata URL's Host, then set this so we can validate the host using this list
      response_hosts: ["localhost:9293"]
    },
    "http://localhost:9292/token" => {
      fingerprint: SamlIdp::Default::FINGERPRINT,
      metadata_url: "http://localhost:9292/saml/metadata",

      # We now validate AssertionConsumerServiceURL will match the MetadataURL set above.
      # *If* it's not going to match your Metadata URL's Host, then set this so we can validate the host using this list
      response_hosts: ["localhost:9292"]
    }
  }

  # Find ServiceProvider metadata_url and fingerprint based on our settings
  config.service_provider.finder = lambda { |issuer_or_entity_id|
    service_providers[issuer_or_entity_id]
  }

  config.name_id.formats = { # All 2.0
    email_address: ->(principal) { principal[:email] },
    transient: ->(principal) { principal[:id] },
    persistent: ->(principal) { principal[:id] }
  }
end

class SAMLServer < Roda
  plugin :render, views: File.expand_path("../assets/html", __dir__)

  plugin :flash
  plugin :common_logger
  plugin :assets, css: "layout.scss", path: File.expand_path("../assets", __dir__)

  secret = ENV.delete("RODAUTH_SESSION_SECRET") || SecureRandom.random_bytes(64)
  plugin :sessions, secret: secret, key: "saml-server.session"

  plugin :rodauth, json: true do
    db DB
    enable :login, :logout, :create_account
    login_return_to_requested_location? true
    account_password_hash_column :ph
    title_instance_variable :@page_title
    login_page_title "SSO"
  end

  route do |r|
    r.assets
    r.rodauth
    rodauth.require_authentication

    r.on "sso" do
      r.get do
        saml_request = SamlIdp::Request.from_deflated_request(r.params["SAMLRequest"])

        text = if saml_request.valid?
                 saml_response = SamlIdp::SamlResponse.new(
                   SecureRandom.uuid,
                   SecureRandom.uuid,
                   "http://localhost:9294",
                   rodauth.account_from_session,
                   saml_request.service_provider.identifier,
                   saml_request.request_id,
                   saml_request.acs_url,
                   OpenSSL::Digest::SHA256,
                   Saml::XML::Namespaces::AuthnContext::ClassRef::PASSWORD,
                   60 * 60,
                   nil,
                   nil
                 ).build

                 <<~HTML
                   <!DOCTYPE html>
                   <html>
                     <head>
                       <meta charset="utf-8">
                       <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
                     </head>
                     <body onload="document.forms[0].submit();" style="visibility:hidden;">
                       <form method="post" action="#{saml_request.acs_url}" class="rodauth" role="form">
                         <input type="hidden" name="SAMLResponse" value="#{saml_response}"/>
                         <input type="hidden" name="RelayState" value="#{request.params['RelayState']}"/>
                         <input type="submit" value="Submit" %>
                       </form>
                     </body>
                   </html>
                 HTML
               else
                 saml_request.errors
               end

        render inline: text
      end
    end
  end
end

DB.freeze

if $PROGRAM_NAME == __FILE__
  require "rackup"

  Rackup::Server.start(
    app: SAMLServer, Port: 9294
  )
end
