# frozen_string_literal: true

require "onelogin/ruby-saml"
require "rodauth/oauth"

module Rodauth
  Feature.define(:oauth_saml_bearer_grant, :OauthSamlBearerGrant) do
    depends :oauth_assertion_base

    auth_value_method :oauth_saml_name_identifier_format, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    auth_value_method :oauth_saml_idp_cert_check_expiration, true

    auth_value_method :max_param_bytesize, nil if Rodauth::VERSION >= "2.26.0"

    auth_value_method :oauth_saml_settings_table, :oauth_saml_settings
    %i[
      id oauth_application_id
      idp_cert idp_cert_fingerprint idp_cert_fingerprint_algorithm
      name_identifier_format
      issuer
      audience
      idp_cert_check_expiration
    ].each do |column|
      auth_value_method :"oauth_saml_settings_#{column}_column", column
    end

    translatable_method :oauth_saml_assertion_not_base64_message, "SAML assertion must be in base64 format"
    translatable_method :oauth_saml_assertion_single_issuer_message, "SAML assertion must have a single issuer"
    translatable_method :oauth_saml_settings_not_found_message, "No SAML settings found for issuer"

    auth_methods(
      :require_oauth_application_from_saml2_bearer_assertion_issuer,
      :require_oauth_application_from_saml2_bearer_assertion_subject,
      :account_from_saml2_bearer_assertion
    )

    def oauth_grant_types_supported
      super | %w[urn:ietf:params:oauth:grant-type:saml2-bearer]
    end

    private

    def require_oauth_application_from_saml2_bearer_assertion_issuer(assertion)
      parse_saml_assertion(assertion)

      return unless @saml_settings

      db[oauth_applications_table].where(
        oauth_applications_id_column => @saml_settings[oauth_saml_settings_oauth_application_id_column]
      ).first
    end

    def require_oauth_application_from_saml2_bearer_assertion_subject(assertion)
      parse_saml_assertion(assertion)

      return unless @assertion

      # 3.3.8 - For client authentication, the Subject MUST be the "client_id" of the OAuth client.
      db[oauth_applications_table].where(
        oauth_applications_client_id_column => @assertion.nameid
      ).first
    end

    def account_from_saml2_bearer_assertion(assertion)
      parse_saml_assertion(assertion)

      return unless @assertion

      account_from_bearer_assertion_subject(@assertion.nameid)
    end

    def generate_saml_settings(saml_settings)
      settings = OneLogin::RubySaml::Settings.new

      # issuer
      settings.idp_entity_id = saml_settings[oauth_saml_settings_issuer_column]

      # audience
      settings.sp_entity_id = saml_settings[oauth_saml_settings_audience_column] || token_url

      # recipient
      settings.assertion_consumer_service_url = token_url

      settings.idp_cert = saml_settings[oauth_saml_settings_idp_cert_column]
      settings.idp_cert_fingerprint = saml_settings[oauth_saml_settings_idp_cert_fingerprint_column]
      settings.idp_cert_fingerprint_algorithm = saml_settings[oauth_saml_settings_idp_cert_fingerprint_algorithm_column]

      if settings.idp_cert
        check_idp_cert_expiration = saml_settings[oauth_saml_settings_idp_cert_check_expiration_column]
        check_idp_cert_expiration = oauth_saml_idp_cert_check_expiration if check_idp_cert_expiration.nil?
        settings.security[:check_idp_cert_expiration] = check_idp_cert_expiration
      end
      settings.security[:strict_audience_validation] = true
      settings.security[:want_name_id] = true

      settings.name_identifier_format = saml_settings[oauth_saml_settings_name_identifier_format_column] ||
                                        oauth_saml_name_identifier_format
      settings
    end

    # rubocop:disable Naming/MemoizedInstanceVariableName
    def parse_saml_assertion(assertion)
      return @assertion if defined?(@assertion)

      response = OneLogin::RubySaml::Response.new(assertion)

      # The SAML Assertion XML data MUST be encoded using base64url
      redirect_response_error("invalid_grant", oauth_saml_assertion_not_base64_message) unless response.send(:base64_encoded?, assertion)

      # 1. The Assertion's <Issuer> element MUST contain a unique identifier
      # for the entity that issued the Assertion.
      redirect_response_error("invalid_grant", oauth_saml_assertion_single_issuer_message) unless response.issuers.size == 1

      @saml_settings = db[oauth_saml_settings_table].where(
        oauth_saml_settings_issuer_column => response.issuers.first
      ).first

      redirect_response_error("invalid_grant", oauth_saml_settings_not_found_message) unless @saml_settings

      response.settings = generate_saml_settings(@saml_settings)

      # 2. The Assertion MUST contain a <Conditions> element ...
      # 3. he Assertion MUST have an expiry that limits the time window ...
      # 4. The Assertion MUST have an expiry that limits the time window ...
      # 5. The <Subject> element MUST contain at least one ...
      # 6. The authorization server MUST reject the entire Assertion if the ...
      # 7. If the Assertion issuer directly authenticated the subject, ...
      redirect_response_error("invalid_grant", response.errors.join("; ")) unless response.is_valid?

      @assertion = response
    end
    # rubocop:enable Naming/MemoizedInstanceVariableName

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:token_endpoint_auth_methods_supported] << "urn:ietf:params:oauth:client-assertion-type:saml2-bearer"
      end
    end
  end
end
