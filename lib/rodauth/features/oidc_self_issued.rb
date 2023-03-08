# frozen_string_literal: true

require "rodauth/oauth"

module Rodauth
  Feature.define(:oidc_self_issued, :OidcSelfIssued) do
    depends :oidc, :oauth_implicit_grant, :oidc_dynamic_client_registration

    auth_value_method :oauth_application_scopes, %w[openid profile email address phone]
    auth_value_method :oauth_jwt_jws_algorithms_supported, %w[RS256]

    SELF_ISSUED_DEFAULT_APPLICATION_PARAMS = {
      "scope" => "openid profile email address phone",
      "response_types" => ["id_token"],
      "subject_type" => "pairwise",
      "id_token_signed_response_alg" => "RS256",
      "request_object_signing_alg" => "RS256",
      "grant_types" => %w[implicit]
    }.freeze

    def oauth_application
      return @oauth_application if defined?(@oauth_application)

      return super unless (registration = param_or_nil("registration"))

      # self-issued!
      redirect_uri = param_or_nil("client_id")

      registration_params = JSON.parse(registration)

      registration_params = SELF_ISSUED_DEFAULT_APPLICATION_PARAMS.merge(registration_params)

      client_params = validate_client_registration_params(registration_params)

      request.params["redirect_uri"] = client_params[oauth_applications_client_id_column] = redirect_uri
      client_params[oauth_applications_redirect_uri_column] ||= redirect_uri

      @oauth_application = client_params
    end

    private

    def oauth_response_types_supported
      %w[id_token]
    end

    def request_object_signing_alg_values_supported
      %w[none RS256]
    end

    def id_token_claims(oauth_grant, signing_algorithm)
      claims = super

      return claims unless claims[:client_id] == oauth_grant[oauth_grants_redirect_uri_column]

      # https://openid.net/specs/openid-connect-core-1_0.html#SelfIssued - 7.4

      pub_key = oauth_jwt_public_keys[signing_algorithm]
      pub_key = pub_key.first if pub_key.is_a?(Array)
      claims[:sub_jwk] = sub_jwk = jwk_export(pub_key)

      claims[:iss] = "https://self-issued.me"

      claims[:aud] = oauth_grant[oauth_grants_redirect_uri_column]

      jwk_thumbprint = jwk_thumbprint(sub_jwk)

      claims[:sub] = Base64.urlsafe_encode64(jwk_thumbprint, padding: false)

      claims
    end
  end
end
