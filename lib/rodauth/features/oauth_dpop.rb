# frozen_string_literal: true

require "rodauth/oauth"
require "logger"

module Rodauth
  Feature.define(:oauth_dpop, :OauthDpop) do
    depends :oauth_jwt, :oauth_authorize_base

    auth_value_method :oauth_invalid_token_error_response_status, 401
    auth_value_method :oauth_multiple_auth_methods_response_status, 401
    auth_value_method :oauth_access_token_dpop_bound_response_status, 401

    translatable_method :oauth_invalid_dpop_proof_message, "Invalid DPoP proof"
    translatable_method :oauth_multiple_auth_methods_message, "Multiple methods used to include access token"
    auth_value_method :oauth_multiple_dpop_proofs_error_code, "invalid_request"
    translatable_method :oauth_multiple_dpop_proofs_message, "Multiple DPoP proofs used"
    auth_value_method :oauth_invalid_dpop_jkt_error_code, "invalid_dpop_proof"
    translatable_method :oauth_invalid_dpop_jkt_message, "Invalid DPoP JKT"
    auth_value_method :oauth_invalid_dpop_jti_error_code, "invalid_dpop_proof"
    translatable_method :oauth_invalid_dpop_jti_message, "Invalid DPoP jti"
    auth_value_method :oauth_invalid_dpop_htm_error_code, "invalid_dpop_proof"
    translatable_method :oauth_invalid_dpop_htm_message, "Invalid DPoP htm"
    auth_value_method :oauth_invalid_dpop_htu_error_code, "invalid_dpop_proof"
    translatable_method :oauth_invalid_dpop_htu_message, "Invalid DPoP htu"
    translatable_method :oauth_access_token_dpop_bound_message, "DPoP bound access token requires DPoP proof"

    translatable_method :oauth_use_dpop_nonce_message, "DPoP nonce is required"

    auth_value_method :oauth_dpop_bound_access_tokens, false
    auth_value_method :oauth_dpop_use_nonce, false
    auth_value_method :oauth_dpop_nonce_expires_in, 5 # 5 seconds
    auth_value_method :oauth_dpop_signing_alg_values_supported,
                      %w[
                        RS256
                        RS384
                        RS512
                        PS256
                        PS384
                        PS512
                        ES256
                        ES384
                        ES512
                        ES256K
                      ]

    auth_value_method :oauth_applications_dpop_bound_access_tokens_column, :dpop_bound_access_tokens
    auth_value_method :oauth_grants_dpop_jkt_column, :dpop_jkt

    def require_oauth_authorization(*scopes)
      @dpop_access_token = fetch_access_token_from_authorization_header("dpop")

      unless @dpop_access_token
        authorization_required if oauth_dpop_bound_access_tokens

        # Specifically, such a protected resource MUST reject a DPoP-bound access token received as a bearer token
        redirect_response_error("access_token_dpop_bound") if authorization_token && authorization_token.dig("cnf", "jkt")

        return super
      end

      dpop = fetch_dpop_token

      dpop_claims = validate_dpop_token(dpop)

      # 4.3.12
      validate_ath(dpop_claims, @dpop_access_token)

      @authorization_token = decode_access_token(@dpop_access_token)

      # 4.3.12 - confirm that the public key to which the access token is bound matches the public key from the DPoP proof.
      jkt = authorization_token.dig("cnf", "jkt")

      redirect_response_error("invalid_dpop_jkt") if oauth_dpop_bound_access_tokens && !jkt

      redirect_response_error("invalid_dpop_jkt") unless jkt == @dpop_thumbprint

      super
    end

    private

    def validate_token_params
      dpop = fetch_dpop_token

      unless dpop
        authorization_required if dpop_bound_access_tokens_required?

        return super
      end

      validate_dpop_token(dpop)

      super
    end

    def validate_dpop_token(dpop)
      # 4.3.2
      @dpop_claims = dpop_decode(dpop)
      redirect_response_error("invalid_dpop_proof") unless @dpop_claims

      validate_dpop_jwt_claims(@dpop_claims)

      # 4.3.10
      validate_nonce(@dpop_claims)

      @dpop_claims
    end

    def dpop_decode(dpop)
      # decode first without verifying!
      _, headers = jwt_decode_no_key(dpop)

      redirect_response_error("invalid_dpop_proof") unless verify_dpop_jwt_headers(headers)

      dpop_jwk = headers["jwk"]

      jwt_decode(
        dpop,
        jws_key: jwk_key(dpop_jwk),
        jws_algorithm: headers["alg"],
        verify_iss: false,
        verify_aud: false,
        verify_jti: false
      )
    end

    def verify_dpop_jwt_headers(headers)
      # 4.3.4 - A field with the value dpop+jwt
      return false unless headers["typ"] == "dpop+jwt"

      # 4.3.5 - It MUST NOT be none or an identifier for a symmetric algorithm
      alg = headers["alg"]
      return false unless alg && oauth_dpop_signing_alg_values_supported.include?(alg)

      dpop_jwk = headers["jwk"]

      return false unless dpop_jwk

      # 4.3.7 - It MUST NOT contain a private key.
      return false if private_jwk?(dpop_jwk)

      # store thumbprint for future assertions
      @dpop_thumbprint = jwk_thumbprint(dpop_jwk)

      true
    end

    def validate_dpop_jwt_claims(claims)
      jti = claims["jti"]

      unless jti && jti == Digest::SHA256.hexdigest("#{request.request_method}:#{request.url}:#{claims['iat']}")
        redirect_response_error("invalid_dpop_jti")
      end

      htm = claims["htm"]

      # 4.3.8 - Check if htm matches the request method
      redirect_response_error("invalid_dpop_htm") unless htm && htm == request.request_method

      htu = claims["htu"]

      # 4.3.9 - Check if htu matches the request URL
      redirect_response_error("invalid_dpop_htu") unless htu && htu == request.url
    end

    def validate_ath(claims, access_token)
      # When the DPoP proof is used in conjunction with the presentation of an access token in protected resource access
      # the DPoP proof MUST also contain the following claim
      ath = claims["ath"]

      redirect_response_error("invalid_token") unless ath

      # The value MUST be the result of a base64url encoding of the SHA-256 hash of the ASCII encoding of
      # the associated access token's value.
      redirect_response_error("invalid_token") unless ath == Base64.urlsafe_encode64(Digest::SHA256.digest(access_token), padding: false)
    end

    def validate_nonce(claims)
      nonce = claims["nonce"]

      unless nonce
        dpop_nonce_required(claims) if oauth_dpop_use_nonce

        return
      end

      dpop_nonce_required(claims) unless valid_dpop_nonce?(nonce)
    end

    def jwt_claims(oauth_grant)
      claims = super
      if @dpop_thumbprint
        # the authorization server associates the issued access token with the
        # public key from the DPoP proof
        claims[:cnf] = { jkt: @dpop_thumbprint }
      end
      claims
    end

    def generate_token(grant_params = {}, should_generate_refresh_token = true)
      # When an authorization server supporting DPoP issues a refresh token to a public client
      # that presents a valid DPoP proof at the token endpoint, the refresh token MUST be bound to the respective public key.
      grant_params[oauth_grants_dpop_jkt_column] = @dpop_thumbprint if @dpop_thumbprint
      super
    end

    def oauth_grant_by_refresh_token_ds(_token, revoked: false)
      ds = super
      # The binding MUST be validated when the refresh token is later presented to get new access tokens.
      ds = ds.where(oauth_grants_dpop_jkt_column => nil)
      ds = ds.or(oauth_grants_dpop_jkt_column => @dpop_thumbprint) if @dpop_thumbprint
      ds
    end

    def oauth_grant_by_token_ds(_token)
      ds = super
      # The binding MUST be validated when the refresh token is later presented to get new access tokens.
      ds = ds.where(oauth_grants_dpop_jkt_column => nil)
      ds = ds.or(oauth_grants_dpop_jkt_column => @dpop_thumbprint) if @dpop_thumbprint
      ds
    end

    def json_access_token_payload(oauth_grant)
      payload = super
      # 5. A token_type of DPoP MUST be included in the access token response to
      # signal to the client that the access token was bound to its DPoP key
      payload["token_type"] = "DPoP" if @dpop_claims
      payload
    end

    def fetch_dpop_token
      dpop = request.env["HTTP_DPOP"]

      return if dpop.nil? || dpop.empty?

      # 4.3.1 - There is not more than one DPoP HTTP request header field.
      redirect_response_error("multiple_dpop_proofs") if dpop.split(";").size > 1

      dpop
    end

    def dpop_bound_access_tokens_required?
      oauth_dpop_bound_access_tokens || (oauth_application && oauth_application[oauth_applications_dpop_bound_access_tokens_column])
    end

    def dpop_use_nonce?
      oauth_dpop_use_nonce || (oauth_application && oauth_application[oauth_applications_dpop_bound_access_tokens_column])
    end

    def valid_dpop_proof_required(error_code = "invalid_dpop_proof")
      if @dpop_access_token
        # protected resource access
        throw_json_response_error(401, error_code)
      else
        redirect_response_error(error_code)
      end
    end

    def dpop_nonce_required(dpop_claims)
      response["DPoP-Nonce"] = generate_dpop_nonce(dpop_claims)

      if @dpop_access_token
        # protected resource access
        throw_json_response_error(401, "use_dpop_nonce")
      else
        redirect_response_error("use_dpop_nonce")
      end
    end

    def www_authenticate_header(payload)
      header = if dpop_bound_access_tokens_required?
                 "DPoP"
               else
                 "#{super}, DPoP"
               end

      error_code = payload["error"]

      unless error_code == "invalid_client"
        header = "#{header} error=\"#{error_code}\""

        if (desc = payload["error_description"])
          header = "#{header} error_description=\"#{desc}\""
        end
      end

      algs = oauth_dpop_signing_alg_values_supported.join(" ")

      "#{header} algs=\"#{algs}\""
    end

    # Nonce

    def generate_dpop_nonce(dpop_claims)
      issued_at = Time.now.to_i

      aud = "#{dpop_claims['htm']}:#{dpop_claims['htu']}"

      nonce_claims = {
        iss: oauth_jwt_issuer,
        iat: issued_at,
        exp: issued_at + oauth_dpop_nonce_expires_in,
        aud: aud
      }

      jwt_encode(nonce_claims)
    end

    def valid_dpop_nonce?(nonce)
      nonce_claims = jwt_decode(nonce, verify_aud: false, verify_jti: false)

      return false unless nonce_claims

      jti = nonce_claims["jti"]

      return false unless jti

      return false unless jti == Digest::SHA256.hexdigest("#{request.request_method}:#{request.url}:#{nonce_claims['iat']}")

      return false unless nonce_claims.key?("aud")

      htm, htu = nonce_claims["aud"].split(":", 2)

      htm == request.request_method && htu == request.url
    end

    def json_token_introspect_payload(grant_or_claims)
      claims = super

      return claims unless grant_or_claims

      if (jkt = grant_or_claims.dig("cnf", "jkt"))
        (claims[:cnf] ||= {})[:jkt] = jkt
        claims[:token_type] = "DPoP"
      end

      claims
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:dpop_signing_alg_values_supported] = oauth_dpop_signing_alg_values_supported
      end
    end
  end
end
