module Rodauth
  Feature.define(:oauth_dpop, :OauthDPoP) do
    depends :oauth_base, :oauth_jwt_base

    auth_value_method :oauth_dpop_bound_access_tokens, false

    %i[dpop_signing_alg_values_supported dpop_bound_access_tokens].each do |column|
      auth_value_method :"oauth_applications_#{column}_column"
    end

    translatable_method :oauth_invalid_dpop_proof_message, "Invalid DPoP key binding"

    auth_value_method :max_param_bytesize, nil if Rodauth::VERSION >= "2.26.0"

    private

    if defined?(JSON::JWT)
      # json-jwt

      auth_value_method :oauth_dpop_signing_alg_values_supported, %w[
        HS256 HS384 HS512
        RS256 RS384 RS512
        PS256 PS384 PS512
        ES256 ES384 ES512 ES256K
      ]

    elsif defined?(JWT)
      # ruby-jwt

      auth_value_method :oauth_dpop_signing_alg_values_supported, %w[
        HS256 HS384 HS512 HS512256
        RS256 RS384 RS512
        ED25519
        ES256 ES384 ES512
        PS256 PS384 PS512
      ]
    end

    def raw_header(key)
      request.headers[key]
    end

    def header_or_nil(key)
      value = raw_header(key)
      redirect_response_error(:oauth_invalid_dpop_proof_message) if dpop_bound_access_tokens?

      # return if value.nil?

      value = value.to_s
      value = over_max_bytesize_param_value(key, value) if max_param_bytesize && value.bytesize > max_param_bytesize
      null_byte_parameter_value(key, value) if value.include?("\0")
      value
    end

    def dpop_bound_access_tokens?
      return @dpop_bound_access_tokens if defined?(@dpop_bound_access_tokens)

      @dpop_bound_access_tokens = (oauth_application[oauth_applications_dpop_bound_access_tokens_column] if oauth_application)
      @dpop_bound_access_tokens = oauth_dpop_bound_access_tokens if @dpop_bound_access_tokens.nil?
      @dpop_bound_access_tokens
    end

    def validate_token_params
      dpop_header = header_or_nil('DPoP')
      return redirect_response_error("invalid_dpop_header") unless dpop_header && oauth_application

      claims = decode_dpop_header(dpop_header)
      return redirect_response_error("invalid_dpop_header") unless claims

      validate_dpop_claims(claims, dpop_header)

      super
    end

    def validate_dpop_claims(claims, dpop_header)
      validate_typ_claim(claims['typ'])
      validate_alg_claim(claims['alg'])
      validate_jwk_claim_and_verify_signature(claims['jwk'], dpop_header, claims['alg'])
      validate_htm_and_htu_claims(claims['htm'], claims['htu'])
      verify_jti(claims['jti'], claims)
      validate_ath_claim(claims['ath'])
    end

    def validate_typ_claim(typ)
      redirect_response_error('Invalid "typ" claim') unless typ == 'dpop+jwt'
    end

    def validate_alg_claim(alg)
      redirect_response_error('Invalid "alg" claim') unless alg && !alg.eql?('none') && (alg.start_with?('RS') || alg.start_with?('PS') || alg.start_with?('ES') || alg.start_with?('HS'))
    end
  end
end

def validate_jwk_claim_and_verify_signature(jwk, dpop_header, alg)
  redirect_response_error('Invalid "jwk" claim') unless jwk
  public_key = OpenSSL::PKey::RSA.new(Base64.urlsafe_decode64(jwk))
  JWT.decode(dpop_header, public_key, true, { algorithm: alg })
end

def validate_htm_and_htu_claims(htm, htu)
  redirect_response_error('Invalid "htm" claim') unless htm == request.request_method
  redirect_response_error('Invalid "htu" claim') unless htu == request.url
end

def validate_jti_claim(jti)
  # TODO: Replace global variable with a safer data store like a database or cache
  verify_jti(jti)
end

def validate_ath_claim(ath_claim)
  access_token = request.env['HTTP_AUTHORIZATION']&.split&.last
  return unless access_token

  ath = Digest::SHA256.base64digest(access_token)
  raise Rodauth::OAuthError, 'Invalid "ath" claim' unless ath_claim == ath
end

def decode_dpop_header(dpop_header)
  dpop_sig_options = {
    dpop_signing_alg_value: oauth_application[oauth_applications_dpop_signing_alg_column]
  }

  jwks = oauth_application_jwks(oauth_application)
  redirect_response_error("invalid_dpop_header") unless jwks
  jwks = JSON.parse(jwks, symbolize_names: true) if jwks.is_a?(String)

  jwt_decode(dpop_header, jwks: jwks, **dpop_sig_options)
end

def dpop_signing_alg_values_supported
  oauth_jwt_jws_algorithms_supported
end

def oauth_server_metadata_body(*)
  super.tap do |data|
    data[:dpop_signing_alg_values_supported
    ] = oauth_dpop_signing_alg_values_supported
  end
end
