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
    email_address: ->(principal) { principal[:email] },
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

  def setup_application
    feature = oauth_feature
    scopes = test_scopes

    testdb = db

    rodauth do
      db testdb
      enable :login, feature
      login_return_to_requested_location? true
      oauth_application_default_scope scopes.first
      oauth_application_scopes scopes
    end

    encode_authn_response = method(:encode_authn_response)

    roda do |r|
      r.rodauth

      # SAML Redirect Binding
      r.on "saml-login" do
        rodauth.require_authentication

        r.get do
          @saml_request = SamlIdp::Request.from_deflated_request(request.params["SAMLRequest"])

          if @saml_request.valid?
            @saml_response = encode_authn_response.call(
              rodauth.account_from_session,
              request_id: @saml_request.request_id,
              audience_uri: @saml_request.issuer,
              acs_url: @saml_request.acs_url
            )
            <<~HTML
              <!DOCTYPE html>
              <html>
                <head>
                  <meta charset="utf-8">
                  <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
                </head>
                <body onload="document.forms[0].submit();" style="visibility:hidden;">
                  <form method="post" action="#{@saml_request.acs_url}" class="rodauth" role="form">
                    <input type="hidden" name="SAMLResponse" value="#{@saml_response}"/>
                    <input type="hidden" name="RelayState" value="#{request.params['RelayState']}"/>
                    <input type="submit" value="Submit" %>
                  </form>
                </body>
              </html>
            HTML
          else
            @saml_request.errors
          end
        end
      end

      r.on "callback" do
        r.params["SAMLResponse"]
      end

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
    Rodauth::I18n.add
  end

  def oauth_feature
    :oauth_saml
  end

  def login(opts = {})
    visit(opts[:path] || make_saml_request("http://example.com/callback")) unless opts[:visit] == false
    fill_in "Login", with: opts.fetch(:login, "foo@example.com")
    fill_in "Password", with: opts.fetch(:pass, "0123456789")
    click_button "Login"
    # this is needed because this user agent doesn't run javascript
    click_button "Submit"
  end

  def make_saml_request(requested_saml_acs_url)
    auth_request = OneLogin::RubySaml::Authrequest.new
    auth_request.create(saml_settings(requested_saml_acs_url))
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
