# frozen_string_literal: true

require "rodauth/oauth/version"
require "rodauth/oauth/http_extensions"

module Rodauth
  Feature.define(:oauth_jwt, :OauthJwt) do
    depends :oauth_base

    # Recommended to have hmac_secret as well

    auth_value_method :oauth_jwt_subject_type, "public" # fallback subject type: public, pairwise
    auth_value_method :oauth_jwt_subject_secret, nil # salt for pairwise generation

    auth_value_method :oauth_applications_subject_type_column, :subject_type
    auth_value_method :oauth_applications_jwt_public_key_column, :jwt_public_key

    translatable_method :oauth_applications_jwt_public_key_label, "Public key"

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
      :jwks_set,
      :generate_jti,
      :oauth_jwt_issuer,
      :oauth_jwt_audience
    )

    route(:jwks) do |r|
      next unless is_authorization_server?

      r.get do
        json_response_success({ keys: jwks_set }, true)
      end
    end

    def require_oauth_authorization(*scopes)
      authorization_required unless authorization_token

      token_scopes = authorization_token["scope"].split(" ")

      authorization_required unless scopes.any? { |scope| token_scopes.include?(scope) }
    end

    def oauth_token_subject
      return unless authorization_token

      authorization_token["sub"]
    end

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
                                token_url
                              else
                                metadata = authorization_server_metadata

                                return unless metadata

                                metadata[:token_endpoint]
                              end
    end

    def authorization_token
      return @authorization_token if defined?(@authorization_token)

      @authorization_token = begin
        bearer_token = fetch_access_token

        return unless bearer_token

        jwt_token = jwt_decode(bearer_token)

        return unless jwt_token

        return unless jwt_token["sub"]

        jwt_token
      end
    end

    # /token

    def create_token_from_token(_grant, update_params)
      oauth_grant = super
      access_token = _generate_jwt_access_token(oauth_grant)
      oauth_grant[oauth_grants_token_column] = access_token
      oauth_grant
    end

    def generate_token(_grant_params = {}, should_generate_refresh_token = true)
      oauth_grant = super
      access_token = _generate_jwt_access_token(oauth_grant)
      oauth_grant[oauth_grants_token_column] = access_token
      oauth_grant
    end

    def _generate_jwt_access_token(oauth_grant)
      claims = jwt_claims(oauth_grant)

      # one of the points of using jwt is avoiding database lookups, so we put here all relevant
      # token data.
      claims[:scope] = oauth_grant[oauth_grants_scopes_column]

      jwt_encode(claims)
    end

    def _generate_access_token(*)
      # no op
    end

    def jwt_claims(oauth_grant)
      issued_at = Time.now.to_i

      {
        iss: oauth_jwt_issuer, # issuer
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
        sub: jwt_subject(oauth_grant),
        client_id: oauth_application[oauth_applications_client_id_column],

        exp: issued_at + oauth_token_expires_in,
        aud: oauth_jwt_audience
      }
    end

    def jwt_subject(oauth_grant)
      subject_type = if oauth_application
                       oauth_application[oauth_applications_subject_type_column] || oauth_jwt_subject_type
                     else
                       oauth_jwt_subject_type
                     end
      case subject_type
      when "public"
        oauth_grant[oauth_grants_account_id_column] || oauth_grant[oauth_grants_oauth_application_id_column]
      when "pairwise"
        id = oauth_grant[oauth_grants_account_id_column]
        application_id = oauth_grant[oauth_grants_oauth_application_id_column]
        Digest::SHA256.hexdigest("#{id}#{application_id}#{oauth_jwt_subject_secret}")
      else
        raise StandardError, "unexpected subject (#{subject_type})"
      end
    end

    def oauth_grant_by_token(token)
      jwt_decode(token)
    end

    def token_from_application?(grant_or_claims, oauth_application)
      return super if grant_or_claims[oauth_tokens_id_column]

      if grant_or_claims["client_id"]
        grant_or_claims["client_id"] == oauth_application[oauth_applications_client_id_column]
      else
        Array(grant_or_claims["aud"]).include?(oauth_application[oauth_applications_client_id_column])
      end
    end

    def oauth_server_metadata_body(path = nil)
      metadata = super
      metadata.merge! \
        jwks_uri: jwks_url,
        token_endpoint_auth_signing_alg_values_supported: oauth_jwt_keys.keys.uniq
      metadata
    end

    def _jwt_key
      @_jwt_key ||= if oauth_application

                      if (jwks = oauth_application_jwks)
                        jwks = JSON.parse(jwks, symbolize_names: true) if jwks && jwks.is_a?(String)
                        jwks
                      else
                        oauth_application[oauth_applications_jwt_public_key_column]
                      end
                    end
    end

    def _jwt_public_key
      @_jwt_public_key ||= if oauth_application
                             jwks || oauth_application[oauth_applications_jwt_public_key_column]
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

    def oauth_application_jwks
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

      auth_value_method :oauth_jwt_algorithms_supported, %w[
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

      def jwk_import(data)
        JSON::JWK.new(data)
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
                     enc_algs = [jws_encryption_algorithm].compact
                     enc_meths = [jws_encryption_method].compact

                     sig_algs = jws_algorithm ? [jws_algorithm] : jwks.select { |k| k[:use] == "sig" }.map { |k| k[:alg] }
                     sig_algs = sig_algs.compact.map(&:to_sym)

                     jws = JSON::JWT.decode(token, JSON::JWK::Set.new({ keys: jwks }), enc_algs + sig_algs, enc_meths)
                     jws = JSON::JWT.decode(jws.plain_text, JSON::JWK::Set.new({ keys: jwks }), sig_algs) if jws.is_a?(JSON::JWE)
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
            (verify_aud && !verify_aud(claims[:aud], oauth_jwt_audience)) &&
            (verify_jti && !verify_jti(claims[:jti], claims))
          )
          return
        end

        claims
      rescue JSON::JWT::Exception
        nil
      end

      def jwks_set
        @jwks_set ||= [
          *(
            unless oauth_jwt_public_keys.empty?
              oauth_jwt_public_keys.flat_map { |algo, pkeys| Array(pkeys).map { |pkey| JSON::JWK.new(pkey).merge(use: "sig", alg: algo) } }
            end
          ),
          *(
            unless oauth_jwt_jwe_public_keys.empty?
              oauth_jwt_jwe_public_keys.flat_map do |(algo, _enc), pkeys|
                Array(pkeys).map do |pkey|
                  JSON::JWK.new(pkey).merge(use: "enc", alg: algo)
                end
              end
            end
          )
        ].compact
      end

    elsif defined?(JWT)
      # ruby-jwt
      require "rodauth/oauth/jwe_extensions" if defined?(JWE)

      auth_value_method :oauth_jwt_algorithms_supported, %w[
        HS256 HS384 HS512 HS512256
        RS256 RS384 RS512
        ED25519
        ES256 ES384 ES512
        PS256 PS384 PS512
      ]

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

      def jwk_import(data)
        JWT::JWK.import(data).keypair
      end

      def jwt_encode(payload,
                     signing_algorithm: oauth_jwt_keys.keys.first)
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
                                   verify_aud: verify_aud,
                                   aud: oauth_jwt_audience,
                                   verify_jti: (verify_jti ? method(:verify_jti) : false),
                                   verify_iat: true
                                 }
                               else
                                 {}
                               end

        # decode jwt
        if is_authorization_server?
          if jwks
            algorithms = jws_algorithm ? [jws_algorithm] : jwks.select { |k| k[:use] == "sig" }.map { |k| k[:alg] }
            JWT.decode(token, nil, true, algorithms: algorithms, jwks: { keys: jwks }, **verify_claims_params).first
          elsif jws_key
            JWT.decode(token, jws_key, true, algorithms: [jws_algorithm], **verify_claims_params).first
          end
        elsif (jwks = auth_server_jwks_set)
          algorithms = jwks[:keys].select { |k| k[:use] == "sig" }.map { |k| k[:alg] }
          JWT.decode(token, nil, true, jwks: jwks, algorithms: algorithms, **verify_claims_params).first
        end
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

      def jwks_set
        @jwks_set ||= [
          *(
            unless oauth_jwt_public_keys.empty?
              oauth_jwt_public_keys.flat_map do |algo, pkeys|
                Array(pkeys).map do |pkey|
                  JWT::JWK.new(pkey).export.merge(use: "sig", alg: algo)
                end
              end
            end
          ),
          *(
            unless oauth_jwt_jwe_public_keys.empty?
              oauth_jwt_jwe_public_keys.flat_map do |(algo, _enc), pkeys|
                Array(pkeys).map do |pkey|
                  JWT::JWK.new(pkey).export.merge(use: "enc", alg: algo)
                end
              end
            end
          )
        ].compact
      end
    else
      # :nocov:
      def jwk_import(_data)
        raise "#{__method__} is undefined, redefine it or require either \"jwt\" or \"json-jwt\""
      end

      def jwt_encode(_token)
        raise "#{__method__} is undefined, redefine it or require either \"jwt\" or \"json-jwt\""
      end

      def jwt_decode(_token, **)
        raise "#{__method__} is undefined, redefine it or require either \"jwt\" or \"json-jwt\""
      end

      def jwks_set
        raise "#{__method__} is undefined, redefine it or require either \"jwt\" or \"json-jwt\""
      end
      # :nocov:
    end

    def validate_oauth_revoke_params
      token_hint = param_or_nil("token_type_hint")

      throw(:rodauth_error) if !token_hint || token_hint == "access_token"

      super
    end

    def jwt_response_success(jwt, cache = false)
      response.status = 200
      response["Content-Type"] ||= "application/jwt"
      if cache
        # defaulting to 1-day for everyone, for now at least
        max_age = 60 * 60 * 24
        response["Cache-Control"] = "private, max-age=#{max_age}"
      else
        response["Cache-Control"] = "no-store"
        response["Pragma"] = "no-cache"
      end
      return_response(jwt)
    end
  end
end
