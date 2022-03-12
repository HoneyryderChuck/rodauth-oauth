# frozen-string-literal: true

require "onelogin/ruby-saml"

module Rodauth
  Feature.define(:oauth_saml_bearer_grant, :OauthSamlBearerGrant) do
    depends :oauth_assertion_base

    auth_value_method :oauth_saml_cert_fingerprint, "9E:65:2E:03:06:8D:80:F2:86:C7:6C:77:A1:D9:14:97:0A:4D:F4:4D"
    auth_value_method :oauth_saml_cert, nil
    auth_value_method :oauth_saml_cert_fingerprint_algorithm, nil
    auth_value_method :oauth_saml_name_identifier_format, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

    auth_value_method :oauth_saml_security_authn_requests_signed, true
    auth_value_method :oauth_saml_security_metadata_signed, true
    auth_value_method :oauth_saml_security_digest_method, XMLSecurity::Document::SHA1
    auth_value_method :oauth_saml_security_signature_method, XMLSecurity::Document::RSA_SHA1

    auth_value_methods(
      :require_oauth_application_from_saml2_bearer_assertion_issuer,
      :require_oauth_application_from_saml2_bearer_assertion_subject,
      :account_from_saml2_bearer_assertion
    )

    private

    def require_oauth_application_from_saml2_bearer_assertion_issuer(assertion)
      saml = saml_assertion(assertion)

      return unless saml

      db[oauth_applications_table].where(
        oauth_applications_homepage_url_column => saml.issuers
      ).first
    end

    def require_oauth_application_from_saml2_bearer_assertion_subject(assertion)
      saml = saml_assertion(assertion)

      return unless saml

      db[oauth_applications_table].where(
        oauth_applications_client_id_column => saml.nameid
      ).first
    end

    def account_from_saml2_bearer_assertion(assertion)
      saml = saml_assertion(assertion)

      return unless saml

      account_from_bearer_assertion_subject(saml.nameid)
    end

    def saml_assertion(assertion)
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_cert = oauth_saml_cert
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

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:grant_types_supported] << "urn:ietf:params:oauth:grant-type:saml2-bearer"
        data[:token_endpoint_auth_methods_supported] << "urn:ietf:params:oauth:client-assertion-type:saml2-bearer"
      end
    end
  end
end
