# frozen-string-literal: true

require "onelogin/ruby-saml"

module Rodauth
  Feature.define(:oauth_saml_bearer_grant, :OauthSamlBearerGrant) do
    depends :oauth

    auth_value_method :oauth_saml_cert_fingerprint, "9E:65:2E:03:06:8D:80:F2:86:C7:6C:77:A1:D9:14:97:0A:4D:F4:4D"
    auth_value_method :oauth_saml_cert_fingerprint_algorithm, nil
    auth_value_method :oauth_saml_name_identifier_format, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

    auth_value_method :oauth_saml_security_authn_requests_signed, false
    auth_value_method :oauth_saml_security_metadata_signed, false
    auth_value_method :oauth_saml_security_digest_method, XMLSecurity::Document::SHA1
    auth_value_method :oauth_saml_security_signature_method, XMLSecurity::Document::RSA_SHA1

    private

    def require_oauth_application
      grant_type = param("grant_type")

      return if grant_type == "urn:ietf:params:oauth:grant-type:saml2-bearer"

      # request authentication optional for assertions
      unless param("client_assertion_type") == "urn:ietf:params:oauth:client-assertion-type:saml2-bearer" &&
             (assertion = param_or_nil("client_assertion"))
        return super
      end

      saml = saml_assertion(assertion)

      redirect_response_error("invalid_grant") unless saml

      # For client authentication, the Subject MUST be the "client_id" of the OAuth client.
      @oauth_application = db[oauth_applications_table].where(
        oauth_applications_client_id_column => saml.nameid
      ).first

      redirect_response_error("invalid_grant") unless @oauth_application
    end

    def saml_assertion(assertion)
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_cert_fingerprint = oauth_saml_cert_fingerprint
      settings.idp_cert_fingerprint_algorithm = oauth_saml_cert_fingerprint_algorithm
      settings.name_identifier_format = oauth_saml_name_identifier_format
      settings.security[:authn_requests_signed] = oauth_saml_security_authn_requests_signed
      settings.security[:metadata_signed] = oauth_saml_security_metadata_signed
      settings.security[:digest_method] = oauth_saml_security_digest_method
      settings.security[:signature_method] = oauth_saml_security_signature_method

      response = OneLogin::RubySaml::Response.new(assertion, settings: settings, skip_recipient_check: true)

      # 3. he Assertion MUST have an expiry that limits the time window ...
      # 4. The Assertion MUST have an expiry that limits the time window ...
      # 5. The <Subject> element MUST contain at least one ...
      # 6. The authorization server MUST reject the entire Assertion if the ...
      # 7. If the Assertion issuer directly authenticated the subject, ...
      redirect_response_error("invalid_grant") unless response.is_valid?

      # In order to issue an access token response as described in OAuth 2.0
      # [RFC6749] or to rely on an Assertion for client authentication, the
      # authorization server MUST validate the Assertion according to the
      # criteria below.

      # 1. The Assertion's <Issuer> element MUST contain a unique identifier
      # for the entity that issued the Assertion.
      redirect_response_error("invalid_grant") unless response.issuers.size == 1

      # 2. in addition to the URI references
      # discussed there, the token endpoint URL of the authorization
      # server MAY be used as a URI that identifies the authorization
      # server as an intended audience.  The authorization server MUST
      # reject any Assertion that does not contain its own identity as
      # the intended audience.
      redirect_response_error("invalid_grant") if response.audiences && !response.audiences.include?(token_url)

      response
    end

    def validate_oauth_token_params
      return super unless param("grant_type") == "urn:ietf:params:oauth:grant-type:saml2-bearer"

      redirect_response_error("invalid_grant") unless param_or_nil("assertion")
    end

    def create_oauth_token(grant_type)
      if grant_type == "urn:ietf:params:oauth:grant-type:saml2-bearer"
        create_oauth_token_from_saml_assertion
      else
        super
      end
    end

    def create_oauth_token_from_saml_assertion
      # A.  For the authorization grant, the Subject typically
      # identifies an authorized accessor for which the access token
      # is being requested
      assertion = saml_assertion(param("assertion"))

      account = db[accounts_table].where(login_column => assertion.nameid).first

      redirect_response_error("invalid_grant") unless account

      @oauth_application = db[oauth_applications_table].where(
        oauth_applications_homepage_url_column => assertion.issuers
      ).first

      redirect_response_error("invalid_grant") unless @oauth_application

      grant_scopes = if param_or_nil("scope")
                       redirect_response_error("invalid_grant") unless check_valid_scopes?
                       scopes
                     else
                       @oauth_application[oauth_applications_scopes_column]
                     end

      # https://datatracker.ietf.org/doc/html/rfc7521#section-4.1
      create_params = {
        oauth_tokens_account_id_column => account[account_id_column],
        oauth_tokens_oauth_application_id_column => @oauth_application[oauth_applications_id_column],
        oauth_tokens_scopes_column => grant_scopes
      }

      generate_oauth_token(create_params, false)
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:grant_types_supported] << "urn:ietf:params:oauth:grant-type:saml2-bearer"
      end
    end
  end
end
