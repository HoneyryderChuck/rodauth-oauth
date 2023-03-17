# frozen_string_literal: true

require "rodauth/oauth"

module Rodauth
  Feature.define(:oauth_jwt_secured_authorization_response_mode, :OauthJwtSecuredAuthorizationResponseMode) do
    depends :oauth_authorize_base, :oauth_jwt_base

    auth_value_method :oauth_authorization_response_mode_expires_in, 60 * 5 # 5 minutes

    auth_value_method :oauth_applications_authorization_signed_response_alg_column, :authorization_signed_response_alg
    auth_value_method :oauth_applications_authorization_encrypted_response_alg_column, :authorization_encrypted_response_alg
    auth_value_method :oauth_applications_authorization_encrypted_response_enc_column, :authorization_encrypted_response_enc

    auth_value_methods(
      :authorization_signing_alg_values_supported,
      :authorization_encryption_alg_values_supported,
      :authorization_encryption_enc_values_supported
    )

    def oauth_response_modes_supported
      jwt_response_modes = %w[jwt]
      jwt_response_modes.push("query.jwt", "form_post.jwt") if features.include?(:oauth_authorization_code_grant)
      jwt_response_modes << "fragment.jwt" if features.include?(:oauth_implicit_grant)

      super | jwt_response_modes
    end

    def authorization_signing_alg_values_supported
      oauth_jwt_jws_algorithms_supported
    end

    def authorization_encryption_alg_values_supported
      oauth_jwt_jwe_algorithms_supported
    end

    def authorization_encryption_enc_values_supported
      oauth_jwt_jwe_encryption_methods_supported
    end

    private

    def oauth_response_modes_for_code_supported
      return [] unless features.include?(:oauth_authorization_code_grant)

      super | %w[query.jwt form_post.jwt jwt]
    end

    def oauth_response_modes_for_token_supported
      return [] unless features.include?(:oauth_implicit_grant)

      super | %w[fragment.jwt jwt]
    end

    def authorize_response(params, mode)
      return super unless mode.end_with?("jwt")

      response_type = param_or_nil("response_type")

      redirect_url = URI.parse(redirect_uri)

      jwt = jwt_encode_authorization_response_mode(params)

      if mode == "query.jwt" || (mode == "jwt" && response_type == "code")
        return super unless features.include?(:oauth_authorization_code_grant)

        params = ["response=#{CGI.escape(jwt)}"]
        params << redirect_url.query if redirect_url.query
        redirect_url.query = params.join("&")
        redirect(redirect_url.to_s)
      elsif mode == "form_post.jwt"
        return super unless features.include?(:oauth_authorization_code_grant)

        response["Content-Type"] = "text/html"
        body = form_post_response_html(redirect_url) do
          "<input type=\"hidden\" name=\"response\" value=\"#{scope.h(jwt)}\" />"
        end
        response.write(body)
        request.halt
      elsif mode == "fragment.jwt" || (mode == "jwt" && response_type == "token")
        return super unless features.include?(:oauth_implicit_grant)

        params = ["response=#{CGI.escape(jwt)}"]
        params << redirect_url.query if redirect_url.query
        redirect_url.fragment = params.join("&")
        redirect(redirect_url.to_s)
      else
        super
      end
    end

    def _redirect_response_error(redirect_url, params)
      response_mode = param_or_nil("response_mode")
      return super unless response_mode.end_with?("jwt")

      authorize_response(Hash[params], response_mode)
    end

    def jwt_encode_authorization_response_mode(params)
      now = Time.now.to_i
      claims = {
        iss: oauth_jwt_issuer,
        aud: oauth_application[oauth_applications_client_id_column],
        exp: now + oauth_authorization_response_mode_expires_in,
        iat: now
      }.merge(params)

      encode_params = {
        jwks: oauth_application_jwks(oauth_application),
        signing_algorithm: oauth_application[oauth_applications_authorization_signed_response_alg_column],
        encryption_algorithm: oauth_application[oauth_applications_authorization_encrypted_response_alg_column],
        encryption_method: oauth_application[oauth_applications_authorization_encrypted_response_enc_column]
      }.compact

      jwt_encode(claims, **encode_params)
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:authorization_signing_alg_values_supported] = authorization_signing_alg_values_supported
        data[:authorization_encryption_alg_values_supported] = authorization_encryption_alg_values_supported
        data[:authorization_encryption_enc_values_supported] = authorization_encryption_enc_values_supported
      end
    end
  end
end
