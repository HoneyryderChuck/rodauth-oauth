# frozen_string_literal: true

require "rodauth/oauth/version"
require "rodauth/oauth/ttl_store"

module Rodauth
  Feature.define(:oauth_jwt_bearer_grant, :OauthJwtBearerGrant) do
    depends :oauth_assertion_base, :oauth_jwt

    auth_value_methods(
      :require_oauth_application_from_jwt_bearer_assertion_issuer,
      :require_oauth_application_from_jwt_bearer_assertion_subject,
      :account_from_jwt_bearer_assertion
    )

    private

    def require_oauth_application_from_jwt_bearer_assertion_issuer(assertion)
      claims = jwt_assertion(assertion)

      return unless claims

      db[oauth_applications_table].where(
        oauth_applications_client_id_column => claims["iss"]
      ).first
    end

    def require_oauth_application_from_jwt_bearer_assertion_subject(assertion)
      claims = jwt_assertion(assertion)

      return unless claims

      db[oauth_applications_table].where(
        oauth_applications_client_id_column => claims["sub"]
      ).first
    end

    def account_from_jwt_bearer_assertion(assertion)
      claims = jwt_assertion(assertion)

      return unless claims

      account_from_bearer_assertion_subject(claims["sub"])
    end

    def jwt_assertion(assertion)
      jwt_decode(assertion, verify_iss: false)
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:grant_types_supported] << "urn:ietf:params:oauth:grant-type:jwt-bearer"
        data[:token_endpoint_auth_methods_supported] << "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
      end
    end
  end
end
