# frozen-string-literal: true

module Rodauth
  Feature.define(:oauth_jwt) do
    depends :oauth

    auth_value_method :oauth_jwt_token_issuer, "Example"

    auth_value_method :oauth_jwt_key, nil
    auth_value_method :oauth_jwt_public_key, nil
    auth_value_method :oauth_jwt_algorithm, "HS256"

    auth_value_method :oauth_jwt_jwk_key, nil
    auth_value_method :oauth_jwt_jwk_public_key, nil
    auth_value_method :oauth_jwt_jwk_algorithm, "RS256"

    auth_value_method :oauth_jwt_jwe_key, nil
    auth_value_method :oauth_jwt_jwe_public_key, nil
    auth_value_method :oauth_jwt_jwe_algorithm, nil
    auth_value_method :oauth_jwt_jwe_encryption_method, nil

    auth_value_method :oauth_jwt_jwe_copyright, nil
    auth_value_method :oauth_jwt_audience, nil

    auth_value_methods(
      :jwt_encode,
      :jwt_decode,
      :jwks_set
    )

    def require_oauth_authorization(*scopes)
      authorization_required unless authorization_token

      scopes << oauth_application_default_scope if scopes.empty?

      token_scopes = authorization_token["scope"].split(" ")

      authorization_required unless scopes.any? { |scope| token_scopes.include?(scope) }
    end

    private

    def authorization_token
      return @authorization_token if defined?(@authorization_token)

      @authorization_token = jwt_decode(fetch_access_token)
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

      payload = {
        sub: oauth_token[oauth_tokens_account_id_column],
        iss: oauth_jwt_token_issuer, # issuer
        iat: issued_at, # issued at
        #
        # sub  REQUIRED - as defined in section 4.1.2 of [RFC7519].  In case of
        # access tokens obtained through grants where a resource owner is
        # involved, such as the authorization code grant, the value of "sub"
        # SHOULD correspond to the subject identifier of the resource owner.
        # In case of access tokens obtained through grants where no resource
        # owner is involved, such as the client credentials grant, the value
        # of "sub" SHOULD correspond to an identifier the authorization
        # server uses to indicate the client application.
        client_id: oauth_application[oauth_applications_client_id_column],

        exp: issued_at + oauth_token_expires_in,
        aud: oauth_jwt_audience,

        # one of the points of using jwt is avoiding database lookups, so we put here all relevant
        # token data.
        scope: oauth_token[oauth_tokens_scopes_column].gsub(",", " ")
      }

      token = jwt_encode(payload)

      oauth_token[oauth_tokens_token_column] = token
      oauth_token
    end

    def oauth_token_by_token(token, *)
      jwt_decode(token)
    end

    def json_token_introspect_payload(oauth_token)
      return { active: false } unless oauth_token

      return super unless oauth_token["sub"] # naive check on whether it's a jwt token

      {
        active: true,
        scope: oauth_token["scope"],
        client_id: oauth_token["client_id"],
        # username
        token_type: "access_token",
        exp: oauth_token["exp"],
        iat: oauth_token["iat"],
        nbf: oauth_token["nbf"],
        sub: oauth_token["sub"],
        aud: oauth_token["aud"],
        iss: oauth_token["iss"],
        jti: oauth_token["jti"]
      }
    end

    def oauth_server_metadata_body(path)
      metadata = super
      metadata.merge! \
        jwks_uri: oauth_jwks_url,
        token_endpoint_auth_signing_alg_values_supported: [oauth_jwt_algorithm]
      metadata
    end

    def token_from_application?(oauth_token, oauth_application)
      return super unless oauth_token["sub"] # naive check on whether it's a jwt token

      oauth_token["client_id"] == oauth_application[oauth_applications_client_id_column]
    end

    def _jwt_key
      @_jwt_key ||= oauth_jwt_key || oauth_application[oauth_applications_client_secret_column]
    end

    if defined?(JSON::JWT)
      # :nocov:

      # json-jwt
      def jwt_encode(payload)
        jwt = JSON::JWT.new(payload)

        jwt = if oauth_jwt_jwk_key
                jwk = JSON::JWK.new(oauth_jwt_jwk_key)
                jwt.kid = jwk.thumbprint
                jwt.sign(oauth_jwt_jwk_key, oauth_jwt_jwk_algorithm)
              else
                jwt.sign(_jwt_key, oauth_jwt_algorithm)
              end
        if oauth_jwt_jwe_key
          algorithm = oauth_jwt_jwe_algorithm.to_sym if oauth_jwt_jwe_algorithm
          jwt = jwt.encrypt(oauth_jwt_jwe_public_key || oauth_jwt_jwe_key,
                            algorithm,
                            oauth_jwt_jwe_encryption_method.to_sym)
        end
        jwt.to_s
      end

      def jwt_decode(token)
        return @jwt_token if defined?(@jwt_token)

        token = JSON::JWT.decode(token, oauth_jwt_jwe_key).plain_text if oauth_jwt_jwe_key

        @jwt_token = if oauth_jwt_jwk_key
                       jwk = JSON::JWK.new(oauth_jwt_jwk_public_key || oauth_jwt_jwk_key)
                       JSON::JWT.decode(token, jwk)
                     else
                       JSON::JWT.decode(token, oauth_jwt_public_key || _jwt_key)
                     end
      rescue JSON::JWT::Exception
        nil
      end

      def jwks_set
        [
          (if oauth_jwt_jwk_public_key
             JSON::JWK.new(oauth_jwt_jwk_public_key).merge(use: "sig", alg: oauth_jwt_jwk_algorithm)
           end),
          (if oauth_jwt_jwe_public_key
             JSON::JWK.new(oauth_jwt_jwe_public_key).merge(use: "enc", alg: oauth_jwt_jwe_algorithm)
           end)
        ].compact
      end
      # :nocov:
    elsif defined?(JWT)

      # ruby-jwt

      def jwt_encode(payload)
        headers = {}

        key, algorithm = if oauth_jwt_jwk_key
                           jwk_key = JWT::JWK.new(oauth_jwt_jwk_key)
                           # JWK
                           # Currently only supports RSA public keys.
                           headers[:kid] = jwk_key.kid

                           [jwk_key.keypair, oauth_jwt_jwk_algorithm]
                         else
                           # JWS

                           [_jwt_key, oauth_jwt_algorithm]
                         end

        # Use the key and iat to create a unique key per request to prevent replay attacks
        jti_raw = [key, payload[:iat]].join(":").to_s
        jti = Digest::SHA256.hexdigest(jti_raw)

        # @see JWT reserved claims - https://tools.ietf.org/html/draft-jones-json-web-token-07#page-7
        payload[:jti] = jti
        token = JWT.encode(payload, key, algorithm, headers)

        if oauth_jwt_jwe_key
          params = {
            zip: "DEF",
            copyright: oauth_jwt_jwe_copyright
          }
          params[:enc] = oauth_jwt_jwe_encryption_method if oauth_jwt_jwe_encryption_method
          params[:alg] = oauth_jwt_jwe_algorithm if oauth_jwt_jwe_algorithm
          token = JWE.encrypt(token, oauth_jwt_jwe_public_key || oauth_jwt_jwe_key, **params)
        end

        token
      end

      def jwt_decode(token)
        return @jwt_token if defined?(@jwt_token)

        # decrypt jwe
        token = JWE.decrypt(token, oauth_jwt_jwe_key) if oauth_jwt_jwe_key

        # decode jwt
        headers = { algorithms: [oauth_jwt_algorithm] }

        key = if oauth_jwt_jwk_key
                jwk_key = JWT::JWK.new(oauth_jwt_jwk_public_key || oauth_jwt_jwk_key)
                # JWK
                # The jwk loader would fetch the set of JWKs from a trusted source
                jwk_loader = lambda do |options|
                  @cached_keys = nil if options[:invalidate] # need to reload the keys
                  @cached_keys ||= { keys: [jwk_key.export] }
                end

                headers[:algorithms] = [oauth_jwt_jwk_algorithm]
                headers[:jwks] = jwk_loader

                nil
              else
                # JWS
                # worst case scenario, the key is the application key
                oauth_jwt_public_key || _jwt_key
              end
        @jwt_token, = JWT.decode(token, key, true, headers)
        @jwt_token
      rescue JWT::DecodeError
        nil
      end

      def jwks_set
        [
          (if oauth_jwt_jwk_public_key
             JWT::JWK.new(oauth_jwt_jwk_public_key).export.merge(use: "sig", alg: oauth_jwt_jwk_algorithm)
           end),
          (if oauth_jwt_jwe_public_key
             JWT::JWK.new(oauth_jwt_jwe_public_key).export.merge(use: "enc", alg: oauth_jwt_jwe_algorithm)
           end)
        ].compact
      end
    else
      # :nocov:
      def jwt_encode(_token)
        raise "#{__method__} is undefined, redefine it or require either \"jwt\" or \"json-jwt\""
      end

      def jwt_decode(_token)
        raise "#{__method__} is undefined, redefine it or require either \"jwt\" or \"json-jwt\""
      end

      def jwks_set
        raise "#{__method__} is undefined, redefine it or require either \"jwt\" or \"json-jwt\""
      end
      # :nocov:
    end

    route(:oauth_jwks) do |r|
      r.get do
        json_response_success(jwks_set)
      end
    end
  end
end
