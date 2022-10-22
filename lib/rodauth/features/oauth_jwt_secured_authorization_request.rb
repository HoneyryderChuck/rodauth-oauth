# frozen_string_literal: true

require "rodauth/oauth"

module Rodauth
  Feature.define(:oauth_jwt_secured_authorization_request, :OauthJwtSecuredAuthorizationRequest) do
    depends :oauth_authorize_base, :oauth_jwt_base

    auth_value_method :oauth_applications_request_object_signing_alg_column, :request_object_signing_alg
    auth_value_method :oauth_applications_request_object_encryption_alg_column, :request_object_encryption_alg
    auth_value_method :oauth_applications_request_object_encryption_enc_column, :request_object_encryption_enc

    translatable_method :oauth_request_uri_not_supported_message, "request uri is unsupported"
    translatable_method :oauth_invalid_request_object_message, "request object is invalid"

    auth_value_method :max_param_bytesize, nil if Rodauth::VERSION >= "2.26.0"

    private

    # /authorize

    def validate_authorize_params
      # TODO: add support for requst_uri
      redirect_response_error("request_uri_not_supported") if param_or_nil("request_uri")

      request_object = param_or_nil("request")

      return super unless request_object && oauth_application

      if (jwks = oauth_application_jwks(oauth_application))
        jwks = JSON.parse(jwks, symbolize_names: true) if jwks.is_a?(String)
      else
        redirect_response_error("invalid_request_object")
      end

      request_sig_enc_opts = {
        jws_algorithm: oauth_application[oauth_applications_request_object_signing_alg_column],
        jws_encryption_algorithm: oauth_application[oauth_applications_request_object_encryption_alg_column],
        jws_encryption_method: oauth_application[oauth_applications_request_object_encryption_enc_column]
      }.compact

      claims = jwt_decode(request_object, jwks: jwks, verify_jti: false, verify_aud: false, **request_sig_enc_opts)

      redirect_response_error("invalid_request_object") unless claims

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
  end
end
