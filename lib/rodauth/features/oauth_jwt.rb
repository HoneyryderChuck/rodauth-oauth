# frozen-string-literal: true

module Rodauth
  Feature.define(:oauth_jwt) do
    depends :oauth

    auth_value_method :oauth_jwt_token_issuer, "Example"
    auth_value_method :oauth_jwt_secret, nil
    auth_value_method :oauth_jwt_secret_path, nil
    auth_value_method :oauth_jwt_decoding_secret, nil
    auth_value_method :oauth_jwt_decoding_secret_path, nil
    auth_value_method :oauth_jwt_jwk_public_key, nil
    auth_value_method :oauth_jwt_jwk_public_key_path, nil
    auth_value_method :oauth_jwt_algorithm, "HS256"
    auth_value_method :oauth_jwt_audience, nil

    auth_value_methods :generate_jti

    def require_oauth_authorization(*scopes)
      authorization_required unless authorization_token

      scopes << oauth_application_default_scope if scopes.empty?

      token_scopes = authorization_token["scopes"].split(",")

      authorization_required unless scopes.any? { |scope| token_scopes.include?(scope) }
    end

    private

    def authorization_token
      return @authorization_token if defined?(@authorization_token)

      @authorization_token = begin
        value = request.get_header("HTTP_AUTHORIZATION").to_s

        scheme, token = value.split(/ +/, 2)

        return unless scheme == "Bearer"

        # decode jwt

        headers = { algorithms: [oauth_jwt_algorithm] }

        secret = if _jwk_public_key
                   # JWK
                   # The jwk loader would fetch the set of JWKs from a trusted source
                   jwk_loader = lambda do |options|
                     @cached_keys = nil if options[:invalidate] # need to reload the keys
                     @cached_keys ||= { keys: [_jwk_public_key.export] }
                   end

                   headers[:algorithms] = ["RS512"]
                   headers[:jwks] = jwk_loader

                   nil
                 else
                   # JWS
                   # worst case scenario, the secret is the application secret
                   _jwt_decoding_secret
                 end

        token, = JWT.decode(token, secret, true, headers)
        token
      end
    rescue JWT::DecodeError
    end

    def generate_oauth_token(params = {}, should_generate_refresh_token = true)
      create_params = {
        oauth_grants_expires_in_column => Time.now + oauth_token_expires_in
      }.merge(params)

      if should_generate_refresh_token
        refresh_token = oauth_unique_id_generator

        if oauth_tokens_refresh_token_hash_column
          create_params[oauth_tokens_refresh_token_hash_column] = generate_token_hash(refresh_token)
        else
          create_params[oauth_tokens_refresh_token_column] = refresh_token
        end
      end

      oauth_token = _generate_oauth_token(create_params)

      issued_at = Time.current.utc.to_i

      headers = {}

      secret, algorithm = if _jwk_public_key
                            # JWK
                            # Currently only supports RSA public keys.
                            headers[:kid] = _jwk_public_key.kid

                            [jwk.keypair, "RS512"]
                          else
                            # JWS

                            [_jwt_secret, oauth_jwt_algorithm]
                          end

      iat = Time.current.utc.to_i

      # Use the secret and iat to create a unique key per request to prevent replay attacks
      jti_raw = [secret, iat].join(":").to_s
      jti = Digest::MD5.hexdigest(jti_raw)

      payload = {
        sub: oauth_token[oauth_tokens_account_id_column],
        iss: oauth_jwt_token_issuer, # issuer
        iat: iat, # issued at

        # @see JWT reserved claims - https://tools.ietf.org/html/draft-jones-json-web-token-07#page-7
        jti: jti,
        exp: issued_at + oauth_token_expires_in,
        aud: oauth_jwt_audience,

        # one of the points of using jwt is avoiding database lookups, so we put here all relevant
        # token data.
        scopes: oauth_token[oauth_tokens_scopes_column]
      }

      token = JWT.encode(payload, secret, algorithm, headers)
      oauth_token[oauth_tokens_token_column] = token
      oauth_token
    end

    def _jwk_public_key
      @_jwk_public_key ||= begin
        key = if oauth_jwt_jwk_public_key_path
                File.read(oauth_jwt_jwk_public_key_path)
              else
                oauth_jwt_jwk_public_key
              end

        return unless key

        JWT::JWK.new(OpenSSL::PKey::RSA.new(key))
      end
    end

    def _jwt_secret
      @_jwt_secret ||= if oauth_jwt_secret_path
                         File.read(oauth_jwt_secret_path)
                       else
                         # worst case scenario, the secret is the application secret
                         oauth_jwt_secret || oauth_application.client_secret
                       end
    end

    def _jwt_decoding_secret
      @_jwt_decoding_secret ||= if oauth_jwt_decoding_secret_path
                                  File.read(oauth_jwt_decoding_secret_path)
                                else
                                  oauth_jwt_decoding_secret || _jwt_secret
                                end
    end
  end
end
