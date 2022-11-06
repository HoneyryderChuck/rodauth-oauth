# frozen_string_literal: true

require "rodauth/oauth"

module Rodauth
  Feature.define(:oauth_jwt_secured_authorization_request, :OauthJwtSecuredAuthorizationRequest) do
    ALLOWED_REQUEST_URI_CONTENT_TYPES = %w[application/jose application/oauth-authz-req+jwt].freeze

    depends :oauth_authorize_base, :oauth_jwt_base

    auth_value_method :oauth_require_request_uri_registration, false
    auth_value_method :oauth_request_object_signing_alg_allow_none, false

    auth_value_method :oauth_applications_request_uris_column, :request_uris

    auth_value_method :oauth_applications_request_object_signing_alg_column, :request_object_signing_alg
    auth_value_method :oauth_applications_request_object_encryption_alg_column, :request_object_encryption_alg
    auth_value_method :oauth_applications_request_object_encryption_enc_column, :request_object_encryption_enc

    translatable_method :oauth_invalid_request_object_message, "request object is invalid"

    auth_value_method :max_param_bytesize, nil if Rodauth::VERSION >= "2.26.0"

    private

    # /authorize

    def validate_authorize_params
      request_object = param_or_nil("request")

      request_uri = param_or_nil("request_uri")

      return super unless (request_object || request_uri) && oauth_application

      if request_uri
        request_uri = CGI.unescape(request_uri)

        redirect_response_error("invalid_request_uri") unless supported_request_uri?(request_uri, oauth_application)

        response = http_request(request_uri)

        unless response.code.to_i == 200 && ALLOWED_REQUEST_URI_CONTENT_TYPES.include?(response["content-type"])
          redirect_response_error("invalid_request_uri")
        end

        request_object = response.body
      end

      request_sig_enc_opts = {
        jws_algorithm: oauth_application[oauth_applications_request_object_signing_alg_column],
        jws_encryption_algorithm: oauth_application[oauth_applications_request_object_encryption_alg_column],
        jws_encryption_method: oauth_application[oauth_applications_request_object_encryption_enc_column]
      }.compact

      request_sig_enc_opts[:jws_algorithm] ||= "none" if oauth_request_object_signing_alg_allow_none

      if request_sig_enc_opts[:jws_algorithm] == "none"
        jwks = nil
      elsif (jwks = oauth_application_jwks(oauth_application))
        jwks = JSON.parse(jwks, symbolize_names: true) if jwks.is_a?(String)
      else
        redirect_response_error("invalid_request_object")
      end

      claims = jwt_decode(request_object,
                          jwks: jwks,
                          verify_jti: false,
                          verify_iss: false,
                          verify_aud: false,
                          **request_sig_enc_opts)

      redirect_response_error("invalid_request_object") unless claims

      if (iss = claims["iss"]) && (iss != oauth_application[oauth_applications_client_id_column])
        redirect_response_error("invalid_request_object")
      end

      if (aud = claims["aud"]) && !verify_aud(aud, oauth_jwt_issuer)
        redirect_response_error("invalid_request_object")
      end

      # If signed, the Authorization Request
      # Object SHOULD contain the Claims "iss" (issuer) and "aud" (audience)
      # as members, with their semantics being the same as defined in the JWT
      # [RFC7519] specification.  The value of "aud" should be the value of
      # the Authorization Server (AS) "issuer" as defined in RFC8414
      # [RFC8414].
      claims.delete("iss")
      audience = claims.delete("aud")

      redirect_response_error("invalid_request_object") if audience && audience != oauth_jwt_issuer

      claims.each do |k, v|
        request.params[k.to_s] = v
      end

      super
    end

    def supported_request_uri?(request_uri, oauth_application)
      return false unless check_valid_uri?(request_uri)

      request_uris = oauth_application[oauth_applications_request_uris_column]

      request_uris.nil? || request_uris.split(oauth_scope_separator).one? { |uri| request_uri.start_with?(uri) }
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:request_parameter_supported] = true
        data[:request_uri_parameter_supported] = true
        data[:require_request_uri_registration] = oauth_require_request_uri_registration
      end
    end
  end
end
