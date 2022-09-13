# frozen_string_literal: true

require "saml_idp"
require "onelogin/ruby-saml"
require_relative File.join(__dir__, "roda_integration")

SamlIdp.configure do |config|
  service_providers = {
    "http://example.com" => {
      fingerprint: SamlIdp::Default::FINGERPRINT,
      metadata_url: "http://example.com/saml/metadata",

      # We now validate AssertionConsumerServiceURL will match the MetadataURL set above.
      # *If* it's not going to match your Metadata URL's Host, then set this so we can validate the host using this list
      response_hosts: ["example.com"]
    }
  }

  # Find ServiceProvider metadata_url and fingerprint based on our settings
  config.service_provider.finder = lambda { |issuer_or_entity_id|
    service_providers[issuer_or_entity_id]
  }

  config.name_id.formats = { # All 2.0
    email_address: ->(principal) { principal[:email] || principal[:client_id] },
    transient: ->(principal) { principal[:id] },
    persistent: ->(_p) { principal[:id] }
  }
end

class SAMLIntegration < RodaIntegration
  private

  def oauth_application(params = {})
    super(params.merge(
      homepage_url: "http://example.com",
      redirect_uri: "http://example.com/callback"
    ))
  end

  def setup_application(*features)
    features << oauth_feature
    scopes = test_scopes

    testdb = db

    rodauth do
      db testdb
      enable :login, :oauth_authorization_code_grant, *features
      login_return_to_requested_location? true
      oauth_application_scopes scopes
    end

    roda do |r|
      r.rodauth

      r.root do
        flash["error"] || flash["notice"] || "Unauthorized"
      end

      yield(rodauth) if block_given?
      rodauth.require_oauth_authorization

      r.on "private" do
        r.get do
          flash["error"] || flash["notice"] || "Authorized"
        end
      end
    end
  end

  def oauth_feature
    :oauth_saml_bearer_grant
  end

  def default_grant_type
    "saml2-bearer"
  end

  def saml_assertion(principal)
    ENV["ruby-saml/testing"] = "true"
    auth_request = OneLogin::RubySaml::Authrequest.new
    auth_request_url = URI(auth_request.create(saml_settings("http://example.com/callback")))
    auth_request_params = URI.decode_www_form(auth_request_url.query).to_h
    saml_request = SamlIdp::Request.from_deflated_request(auth_request_params["SAMLRequest"])
    encode_authn_response(
      principal,
      request_id: saml_request.request_id,
      audience_uri: "http://example.org/token",
      acs_url: saml_request.acs_url
    )
  end

  def saml_settings(saml_acs_url)
    settings = OneLogin::RubySaml::Settings.new
    settings.assertion_consumer_service_url = saml_acs_url
    settings.issuer = oauth_application[:homepage_url]
    settings.idp_sso_target_url = "http://example.com/saml-login"
    settings.assertion_consumer_logout_service_url = "http://foo.example.com/saml-logout"
    settings.idp_cert_fingerprint = SamlIdp::Default::FINGERPRINT
    settings.name_identifier_format = SamlIdp::Default::NAME_ID_FORMAT
    settings
  end

  def encode_authn_response(principal, request_id:, audience_uri:, acs_url:)
    response_id = SecureRandom.uuid
    reference_id = SecureRandom.uuid
    opt_issuer_uri = "http://example.com"
    my_authn_context_classref = Saml::XML::Namespaces::AuthnContext::ClassRef::PASSWORD
    expiry = 60 * 60

    response = SamlIdp::SamlResponse.new(
      reference_id,
      response_id,
      opt_issuer_uri,
      principal,
      audience_uri,
      request_id,
      acs_url,
      OpenSSL::Digest::SHA256,
      my_authn_context_classref,
      expiry,
      nil,
      nil
    )
    response.build
  end
end
