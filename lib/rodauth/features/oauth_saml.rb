# frozen-string-literal: true

require "onelogin/ruby-saml"

module Rodauth
  Feature.define(:oauth_saml) do
    depends :oauth

    auth_value_method :oauth_saml_cert_fingerprint, "9E:65:2E:03:06:8D:80:F2:86:C7:6C:77:A1:D9:14:97:0A:4D:F4:4D"
    auth_value_method :oauth_saml_cert_fingerprint_algorithm, nil
    auth_value_method :oauth_saml_name_identifier_format, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

    auth_value_method :oauth_saml_security_authn_requests_signed, false
    auth_value_method :oauth_saml_security_metadata_signed, false
    auth_value_method :oauth_saml_security_digest_method, XMLSecurity::Document::SHA1
    auth_value_method :oauth_saml_security_signature_method, XMLSecurity::Document::RSA_SHA1

    SAML_GRANT_TYPE = "http://oauth.net/grant_type/assertion/saml/2.0/bearer"

    # /token

    def require_oauth_application
      # requset authentication optional for assertions
      return super unless param("grant_type") == SAML_GRANT_TYPE && !param_or_nil("client_id")

      # TODO: invalid grant
      authorization_required unless saml_assertion

      redirect_uri = saml_assertion.destination

      @oauth_application = db[oauth_applications_table].where(
        oauth_applications_homepage_url_column => saml_assertion.audiences,
        oauth_applications_redirect_uri_column => redirect_uri
      ).first

      # The Assertion's <Issuer> element MUST contain a unique identifier
      # for the entity that issued the Assertion.
      authorization_required unless saml_assertion.issuers.all? do |issuer|
        issuer.start_with?(@oauth_application[oauth_applications_homepage_url_column])
      end

      authorization_required unless @oauth_application
    end

    private

    def secret_matches?(oauth_application, secret)
      return super unless param_or_nil("assertion")

      true
    end

    def saml_assertion
      return @saml_assertion if defined?(@saml_assertion)

      @saml_assertion = begin
        settings = OneLogin::RubySaml::Settings.new
        settings.idp_cert_fingerprint = oauth_saml_cert_fingerprint
        settings.idp_cert_fingerprint_algorithm = oauth_saml_cert_fingerprint_algorithm
        settings.name_identifier_format = oauth_saml_name_identifier_format
        settings.security[:authn_requests_signed] = oauth_saml_security_authn_requests_signed
        settings.security[:metadata_signed] = oauth_saml_security_metadata_signed
        settings.security[:digest_method] = oauth_saml_security_digest_method
        settings.security[:signature_method] = oauth_saml_security_signature_method

        response = OneLogin::RubySaml::Response.new(param("assertion"), settings: settings, skip_recipient_check: true)

        return unless response.is_valid?

        response
      end
    end

    def validate_oauth_token_params
      return super unless param("grant_type") == SAML_GRANT_TYPE

      redirect_response_error("invalid_client") unless param_or_nil("assertion")

      redirect_response_error("invalid_scope") unless check_valid_scopes?
    end

    def create_oauth_token
      if param("grant_type") == SAML_GRANT_TYPE
        create_oauth_token_from_saml_assertion
      else
        super
      end
    end

    def create_oauth_token_from_saml_assertion
      account = db[accounts_table].where(login_column => saml_assertion.nameid).first

      redirect_response_error("invalid_client") unless oauth_application && account

      create_params = {
        oauth_tokens_account_id_column => account[account_id_column],
        oauth_tokens_oauth_application_id_column => oauth_application[oauth_applications_id_column],
        oauth_tokens_scopes_column => (param_or_nil("scope") || oauth_application[oauth_applications_scopes_column])
      }

      generate_oauth_token(create_params, false)
    end
  end
end
