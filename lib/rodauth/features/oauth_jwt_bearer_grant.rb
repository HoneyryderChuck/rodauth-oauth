# frozen_string_literal: true

require "rodauth/oauth/version"

module Rodauth
  Feature.define(:oauth_jwt_bearer_grant, :OauthJwtBearerGrant) do
    depends :oauth_assertion_base, :oauth_jwt

    auth_value_methods(
      :require_oauth_application_from_jwt_bearer_assertion_issuer,
      :require_oauth_application_from_jwt_bearer_assertion_subject,
      :account_from_jwt_bearer_assertion
    )

    def oauth_token_endpoint_auth_methods_supported
      super | %w[client_secret_jwt private_key_jwt urn:ietf:params:oauth:client-assertion-type:jwt-bearer]
    end

    def oauth_grant_types_supported
      super | %w[urn:ietf:params:oauth:grant-type:jwt-bearer]
    end

    private

    def require_oauth_application_from_jwt_bearer_assertion_issuer(assertion)
      claims = jwt_assertion(assertion)

      return unless claims

      db[oauth_applications_table].where(
        oauth_applications_client_id_column => claims["iss"]
      ).first
    end

    def require_oauth_application_from_jwt_bearer_assertion_subject(assertion)
      claims, header = jwt_decode_no_key(assertion)

      client_id = claims["sub"]

      case header["alg"]
      when "none"
        # do not accept jwts with no alg set
        authorization_required
      when /\AHS/
        require_oauth_application_from_client_secret_jwt(client_id, assertion, header["alg"])
      else
        require_oauth_application_from_private_key_jwt(client_id, assertion)
      end
    end

    def require_oauth_application_from_client_secret_jwt(client_id, assertion, alg)
      oauth_application = db[oauth_applications_table].where(oauth_applications_client_id_column => client_id).first
      authorization_required unless supports_auth_method?(oauth_application, "client_secret_jwt")
      client_secret = oauth_application[oauth_applications_client_secret_column]
      claims = jwt_assertion(assertion, jws_key: client_secret, jws_algorithm: alg)
      authorization_required unless claims && claims["iss"] == client_id
      oauth_application
    end

    def require_oauth_application_from_private_key_jwt(client_id, assertion)
      oauth_application = db[oauth_applications_table].where(oauth_applications_client_id_column => client_id).first
      authorization_required unless supports_auth_method?(oauth_application, "private_key_jwt")
      jwks = oauth_application_jwks(oauth_application)
      claims = jwt_assertion(assertion, jwks: jwks)
      authorization_required unless claims
      oauth_application
    end

    def account_from_jwt_bearer_assertion(assertion)
      claims = jwt_assertion(assertion)

      return unless claims

      account_from_bearer_assertion_subject(claims["sub"])
    end

    def jwt_assertion(assertion, **kwargs)
      claims = jwt_decode(assertion, verify_iss: false, verify_aud: false, **kwargs)
      return unless verify_aud(request.url, claims["aud"])

      claims
    end
  end
end
