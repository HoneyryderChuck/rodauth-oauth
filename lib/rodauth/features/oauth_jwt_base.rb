# frozen_string_literal: true

require "rodauth/oauth"
require "rodauth/oauth/http_extensions"

module Rodauth
  Feature.define(:oauth_jwt_base, :OauthJwtBase) do
    depends :oauth_base

    auth_value_method :oauth_application_jwt_public_key_param, "jwt_public_key"
    auth_value_method :oauth_application_jwks_param, "jwks"

    auth_value_method :oauth_jwt_keys, {}
    auth_value_method :oauth_jwt_public_keys, {}

    auth_value_method :oauth_jwt_jwe_keys, {}
    auth_value_method :oauth_jwt_jwe_public_keys, {}

    auth_value_method :oauth_jwt_jwe_copyright, nil

    auth_value_methods(
      :jwt_encode,
      :jwt_decode,
      :jwt_decode_no_key,
      :generate_jti,
      :oauth_jwt_issuer,
      :oauth_jwt_audience,
      :resource_owner_params_from_jwt_claims
    )

    private

    def oauth_jwt_issuer
      # The JWT MUST contain an "iss" (issuer) claim that contains a
      # unique identifier for the entity that issued the JWT.
      @oauth_jwt_issuer ||= authorization_server_url
    end

    def oauth_jwt_audience
      # The JWT MUST contain an "aud" (audience) claim containing a
      # value that identifies the authorization server as an intended
      # audience.  The token endpoint URL of the authorization server
      # MAY be used as a value for an "aud" element to identify the
      # authorization server as an intended audience of the JWT.
      @oauth_jwt_audience ||= if is_authorization_server?
                                oauth_application[oauth_applications_client_id_column]
                              else
                                metadata = authorization_server_metadata

                                return unless metadata

                                metadata[:token_endpoint]
                              end
    end

    def grant_from_application?(grant_or_claims, oauth_application)
      return super if grant_or_claims[oauth_grants_id_column]

      if grant_or_claims["client_id"]
        grant_or_claims["client_id"] == oauth_application[oauth_applications_client_id_column]
      else
        Array(grant_or_claims["aud"]).include?(oauth_application[oauth_applications_client_id_column])
      end
    end

    def jwt_subject(oauth_grant, client_application = oauth_application)
      account_id = oauth_grant[oauth_grants_account_id_column]

      return account_id.to_s if account_id

      client_application[oauth_applications_client_id_column]
    end

    def resource_owner_params_from_jwt_claims(claims)
      { oauth_grants_account_id_column => claims["sub"] }
    end

    def oauth_server_metadata_body(path = nil)
      metadata = super
      metadata.merge! \
        token_endpoint_auth_signing_alg_values_supported: oauth_jwt_keys.keys.uniq
      metadata
    end

    def _jwt_key
      @_jwt_key ||= (oauth_application_jwks(oauth_application) if oauth_application)
    end

    def _jwt_public_key
      @_jwt_public_key ||= if oauth_application
                             oauth_application_jwks(oauth_application)
                           else
                             _jwt_key
                           end
    end

    # Resource Server only!
    #
    # returns the jwks set from the authorization server.
    def auth_server_jwks_set
      metadata = authorization_server_metadata

      return unless metadata && (jwks_uri = metadata[:jwks_uri])

      jwks_uri = URI(jwks_uri)

      http_request_with_cache(jwks_uri)
    end

    def generate_jti(payload)
      # Use the key and iat to create a unique key per request to prevent replay attacks
      jti_raw = [
        payload[:aud] || payload["aud"],
        payload[:iat] || payload["iat"]
      ].join(":").to_s
      Digest::SHA256.hexdigest(jti_raw)
    end

    def verify_jti(jti, claims)
      generate_jti(claims) == jti
    end

    def verify_aud(expected_aud, aud)
      expected_aud == aud
    end

    def oauth_application_jwks(oauth_application)
      jwks = oauth_application[oauth_applications_jwks_column]

      if jwks
        jwks = JSON.parse(jwks, symbolize_names: true) if jwks.is_a?(String)
        return jwks
      end

      jwks_uri = oauth_application[oauth_applications_jwks_uri_column]

      return unless jwks_uri

      jwks_uri = URI(jwks_uri)

      http_request_with_cache(jwks_uri)
    end

    if defined?(JSON::JWT)
      # json-jwt

      auth_value_method :oauth_jwt_jws_algorithms_supported, %w[
        HS256 HS384 HS512
        RS256 RS384 RS512
        PS256 PS384 PS512
        ES256 ES384 ES512 ES256K
      ]
      auth_value_method :oauth_jwt_jwe_algorithms_supported, %w[
        RSA1_5 RSA-OAEP dir A128KW A256KW
      ]
      auth_value_method :oauth_jwt_jwe_encryption_methods_supported, %w[
        A128GCM A256GCM A128CBC-HS256 A256CBC-HS512
      ]

      def jwk_export(key)
        JSON::JWK.new(key)
      end

      def jwt_encode(payload,
                     jwks: nil,
                     encryption_algorithm: oauth_jwt_jwe_keys.keys.dig(0, 0),
                     encryption_method: oauth_jwt_jwe_keys.keys.dig(0, 1),
                     jwe_key: oauth_jwt_jwe_keys[[encryption_algorithm,
                                                  encryption_method]],
                     signing_algorithm: oauth_jwt_keys.keys.first)
        payload[:jti] = generate_jti(payload)
        jwt = JSON::JWT.new(payload)

        key = oauth_jwt_keys[signing_algorithm] || _jwt_key
        key = key.first if key.is_a?(Array)

        jwk = JSON::JWK.new(key || "")

        jwt = jwt.sign(jwk, signing_algorithm)
        jwt.kid = jwk.thumbprint

        if jwks && (jwk = jwks.find { |k| k[:use] == "enc" && k[:alg] == encryption_algorithm && k[:enc] == encryption_method })
          jwk = JSON::JWK.new(jwk)
          jwe = jwt.encrypt(jwk, encryption_algorithm.to_sym, encryption_method.to_sym)
          jwe.to_s
        elsif jwe_key
          jwe_key = jwe_key.first if jwe_key.is_a?(Array)
          algorithm = encryption_algorithm.to_sym if encryption_algorithm
          meth = encryption_method.to_sym if encryption_method
          jwt.encrypt(jwe_key, algorithm, meth)
        else
          jwt.to_s
        end
      end

      def jwt_decode(
        token,
        jwks: nil,
        jws_algorithm: oauth_jwt_public_keys.keys.first || oauth_jwt_keys.keys.first,
        jws_key: oauth_jwt_keys[jws_algorithm] || _jwt_key,
        jws_encryption_algorithm: oauth_jwt_jwe_keys.keys.dig(0, 0),
        jws_encryption_method: oauth_jwt_jwe_keys.keys.dig(0, 1),
        jwe_key: oauth_jwt_jwe_keys[[jws_encryption_algorithm, jws_encryption_method]] || oauth_jwt_jwe_keys.values.first,
        verify_claims: true,
        verify_jti: true,
        verify_iss: true,
        verify_aud: true,
        **
      )
        jws_key = jws_key.first if jws_key.is_a?(Array)

        if jwe_key
          jwe_key = jwe_key.first if jwe_key.is_a?(Array)
          token = JSON::JWT.decode(token, jwe_key).plain_text
        end

        claims = if is_authorization_server?
                   if jwks
                     jwks = jwks[:keys] if jwks.is_a?(Hash)

                     enc_algs = [jws_encryption_algorithm].compact
                     enc_meths = [jws_encryption_method].compact

                     sig_algs = jws_algorithm ? [jws_algorithm] : jwks.select { |k| k[:use] == "sig" }.map { |k| k[:alg] }
                     sig_algs = sig_algs.compact.map(&:to_sym)

                     # JWKs may be set up without a KID, when there's a single one
                     if jwks.size == 1 && !jwks[0][:kid]
                       key = jwks[0]
                       jwk_key = JSON::JWK.new(key)
                       jws = JSON::JWT.decode(token, jwk_key)
                     else
                       jws = JSON::JWT.decode(token, JSON::JWK::Set.new({ keys: jwks }), enc_algs + sig_algs, enc_meths)
                       jws = JSON::JWT.decode(jws.plain_text, JSON::JWK::Set.new({ keys: jwks }), sig_algs) if jws.is_a?(JSON::JWE)
                     end
                     jws
                   elsif jws_key
                     JSON::JWT.decode(token, jws_key)
                   end
                 elsif (jwks = auth_server_jwks_set)
                   JSON::JWT.decode(token, JSON::JWK::Set.new(jwks))
                 end

        now = Time.now
        if verify_claims && (
            (!claims[:exp] || Time.at(claims[:exp]) < now) &&
            (claims[:nbf] && Time.at(claims[:nbf]) < now) &&
            (claims[:iat] && Time.at(claims[:iat]) < now) &&
            (verify_iss && claims[:iss] != oauth_jwt_issuer) &&
            (verify_aud && !verify_aud(claims[:aud], claims[:client_id])) &&
            (verify_jti && !verify_jti(claims[:jti], claims))
          )
          return
        end

        claims
      rescue JSON::JWT::Exception
        nil
      end

      def jwt_decode_no_key(token)
        jws = JSON::JWT.decode(token, :skip_verification)
        [jws.to_h, jws.header]
      end
    elsif defined?(JWT)
      # ruby-jwt
      require "rodauth/oauth/jwe_extensions" if defined?(JWE)

      auth_value_method :oauth_jwt_jws_algorithms_supported, %w[
        HS256 HS384 HS512 HS512256
        RS256 RS384 RS512
        ED25519
        ES256 ES384 ES512
        PS256 PS384 PS512
      ]

      if defined?(JWE)
        auth_value_methods(
          :oauth_jwt_jwe_algorithms_supported,
          :oauth_jwt_jwe_encryption_methods_supported
        )

        def oauth_jwt_jwe_algorithms_supported
          JWE::VALID_ALG
        end

        def oauth_jwt_jwe_encryption_methods_supported
          JWE::VALID_ENC
        end
      else
        auth_value_method :oauth_jwt_jwe_algorithms_supported, []
        auth_value_method :oauth_jwt_jwe_encryption_methods_supported, []
      end

      def jwk_export(key)
        JWT::JWK.new(key).export
      end

      def jwt_encode(payload,
                     signing_algorithm: oauth_jwt_keys.keys.first, **)
        headers = {}

        key = oauth_jwt_keys[signing_algorithm] || _jwt_key
        key = key.first if key.is_a?(Array)

        case key
        when OpenSSL::PKey::PKey
          jwk = JWT::JWK.new(key)
          headers[:kid] = jwk.kid

          key = jwk.keypair
        end

        # @see JWT reserved claims - https://tools.ietf.org/html/draft-jones-json-web-token-07#page-7
        payload[:jti] = generate_jti(payload)
        JWT.encode(payload, key, signing_algorithm, headers)
      end

      if defined?(JWE)
        def jwt_encode_with_jwe(
          payload,
          jwks: nil,
          encryption_algorithm: oauth_jwt_jwe_keys.keys.dig(0, 0),
          encryption_method: oauth_jwt_jwe_keys.keys.dig(0, 1),
          jwe_key: oauth_jwt_jwe_keys[[encryption_algorithm, encryption_method]],
          **args
        )
          token = jwt_encode_without_jwe(payload, **args)

          return token unless encryption_algorithm && encryption_method

          if jwks && jwks.any? { |k| k[:use] == "enc" }
            JWE.__rodauth_oauth_encrypt_from_jwks(token, jwks, alg: encryption_algorithm, enc: encryption_method)
          elsif jwe_key
            jwe_key = jwe_key.first if jwe_key.is_a?(Array)
            params = {
              zip: "DEF",
              copyright: oauth_jwt_jwe_copyright
            }
            params[:enc] = encryption_method if encryption_method
            params[:alg] = encryption_algorithm if encryption_algorithm
            JWE.encrypt(token, jwe_key, **params)
          else
            token
          end
        end

        alias_method :jwt_encode_without_jwe, :jwt_encode
        alias_method :jwt_encode, :jwt_encode_with_jwe
      end

      def jwt_decode(
        token,
        jwks: nil,
        jws_algorithm: oauth_jwt_public_keys.keys.first || oauth_jwt_keys.keys.first,
        jws_key: oauth_jwt_keys[jws_algorithm] || _jwt_key,
        verify_claims: true,
        verify_jti: true,
        verify_iss: true,
        verify_aud: true
      )
        jws_key = jws_key.first if jws_key.is_a?(Array)

        # verifying the JWT implies verifying:
        #
        # issuer: check that server generated the token
        # aud: check the audience field (client is who he says he is)
        # iat: check that the token didn't expire
        #
        # subject can't be verified automatically without having access to the account id,
        # which we don't because that's the whole point.
        #
        verify_claims_params = if verify_claims
                                 {
                                   verify_iss: verify_iss,
                                   iss: oauth_jwt_issuer,
                                   # can't use stock aud verification, as it's dependent on the client application id
                                   verify_aud: false,
                                   verify_jti: (verify_jti ? method(:verify_jti) : false),
                                   verify_iat: true
                                 }
                               else
                                 {}
                               end

        # decode jwt
        claims = if is_authorization_server?
                   if jwks
                     jwks = jwks[:keys] if jwks.is_a?(Hash)

                     # JWKs may be set up without a KID, when there's a single one
                     if jwks.size == 1 && !jwks[0][:kid]
                       key = jwks[0]
                       algo = key[:alg]
                       key = JWT::JWK.import(key).keypair
                       JWT.decode(token, key, true, algorithms: [algo], **verify_claims_params).first
                     else
                       algorithms = jws_algorithm ? [jws_algorithm] : jwks.select { |k| k[:use] == "sig" }.map { |k| k[:alg] }
                       JWT.decode(token, nil, true, algorithms: algorithms, jwks: { keys: jwks }, **verify_claims_params).first
                     end
                   elsif jws_key
                     JWT.decode(token, jws_key, true, algorithms: [jws_algorithm], **verify_claims_params).first
                   end
                 elsif (jwks = auth_server_jwks_set)
                   algorithms = jwks[:keys].select { |k| k[:use] == "sig" }.map { |k| k[:alg] }
                   JWT.decode(token, nil, true, jwks: jwks, algorithms: algorithms, **verify_claims_params).first
                 end

        return if verify_claims && verify_aud && !verify_aud(claims["aud"], claims["client_id"])

        claims
      rescue JWT::DecodeError, JWT::JWKError
        nil
      end

      if defined?(JWE)
        def jwt_decode_with_jwe(
          token,
          jwks: nil,
          jws_encryption_algorithm: oauth_jwt_jwe_keys.keys.dig(0, 0),
          jws_encryption_method: oauth_jwt_jwe_keys.keys.dig(0, 1),
          jwe_key: oauth_jwt_jwe_keys[[jws_encryption_algorithm, jws_encryption_method]] || oauth_jwt_jwe_keys.values.first,
          **args
        )

          token = if jwks && jwks.any? { |k| k[:use] == "enc" }
                    JWE.__rodauth_oauth_decrypt_from_jwks(token, jwks, alg: jws_encryption_algorithm, enc: jws_encryption_method)
                  elsif jwe_key
                    jwe_key = jwe_key.first if jwe_key.is_a?(Array)
                    JWE.decrypt(token, jwe_key)
                  else
                    token
                  end

          jwt_decode_without_jwe(token, jwks: jwks, **args)
        rescue JWE::DecodeError => e
          jwt_decode_without_jwe(token, jwks: jwks, **args) if e.message.include?("Not enough or too many segments")
        end

        alias_method :jwt_decode_without_jwe, :jwt_decode
        alias_method :jwt_decode, :jwt_decode_with_jwe
      end

      def jwt_decode_no_key(token)
        JWT.decode(token, nil, false)
      end
    else
      # :nocov:
      def jwk_export(_key)
        raise "#{__method__} is undefined, redefine it or require either \"jwt\" or \"json-jwt\""
      end

      def jwt_encode(_token)
        raise "#{__method__} is undefined, redefine it or require either \"jwt\" or \"json-jwt\""
      end

      def jwt_decode(_token, **)
        raise "#{__method__} is undefined, redefine it or require either \"jwt\" or \"json-jwt\""
      end
      # :nocov:
    end
  end
end
