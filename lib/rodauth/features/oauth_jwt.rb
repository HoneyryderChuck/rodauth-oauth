# frozen-string-literal: true

require "rodauth/oauth/ttl_store"

module Rodauth
  Feature.define(:oauth_jwt) do
    depends :oauth

    JWKS = OAuth::TtlStore.new

    # Recommended to have hmac_secret as well

    auth_value_method :oauth_jwt_subject_type, "public" # public, pairwise
    auth_value_method :oauth_jwt_subject_secret, nil # salt for pairwise generation

    auth_value_method :oauth_jwt_token_issuer, nil

    auth_value_method :oauth_application_jws_jwk_column, nil

    auth_value_method :oauth_jwt_key, nil
    auth_value_method :oauth_jwt_public_key, nil
    auth_value_method :oauth_jwt_algorithm, "HS256"

    auth_value_method :oauth_jwt_jwe_key, nil
    auth_value_method :oauth_jwt_jwe_public_key, nil
    auth_value_method :oauth_jwt_jwe_algorithm, nil
    auth_value_method :oauth_jwt_jwe_encryption_method, nil

    # values used for rotating keys
    auth_value_method :oauth_jwt_legacy_public_key, nil
    auth_value_method :oauth_jwt_legacy_algorithm, nil

    auth_value_method :oauth_jwt_jwe_copyright, nil
    auth_value_method :oauth_jwt_audience, nil

    auth_value_method :request_uri_not_supported_message, "request uri is unsupported"
    auth_value_method :invalid_request_object_message, "request object is invalid"

    auth_value_methods(
      :jwt_encode,
      :jwt_decode,
      :jwks_set,
      :last_account_login_at,
      :generate_jti,
      :verify_jti
    )

    route(:jwks) do |r|
      next unless is_authorization_server?

      r.get do
        json_response_success({ keys: jwks_set }, true)
      end
    end

    def require_oauth_authorization(*scopes)
      authorization_required unless authorization_token

      scopes << oauth_application_default_scope if scopes.empty?

      token_scopes = authorization_token["scope"].split(" ")

      authorization_required unless scopes.any? { |scope| token_scopes.include?(scope) }
    end

    private

    unless method_defined?(:last_account_login_at)
      def last_account_login_at
        nil
      end
    end

    def issuer
      @issuer ||= oauth_jwt_token_issuer || authorization_server_url
    end

    def authorization_token
      return @authorization_token if defined?(@authorization_token)

      @authorization_token = begin
        bearer_token = fetch_access_token

        return unless bearer_token

        jwt_token = jwt_decode(bearer_token)

        return unless jwt_token

        return if jwt_token["iss"] != issuer ||
                  (oauth_jwt_audience && jwt_token["aud"] != oauth_jwt_audience) ||
                  !jwt_token["sub"]

        jwt_token
      end
    end

    # /authorize

    def validate_oauth_grant_params
      # TODO: add support for requst_uri
      redirect_response_error("request_uri_not_supported") if param_or_nil("request_uri")

      request_object = param_or_nil("request")

      return super unless request_object && oauth_application

      jws_jwk = if oauth_application[oauth_application_jws_jwk_column]
                  jwk = oauth_application[oauth_application_jws_jwk_column]

                  jwk = JSON.parse(jwk, symbolize_names: true) if jwk && jwk.is_a?(String)
                else
                  redirect_response_error("invalid_request_object")
                end

      claims = jwt_decode(request_object, jws_key: jwk_import(jws_jwk), jws_algorithm: jwk[:alg], verify_jti: false)

      redirect_response_error("invalid_request_object") unless claims

      # If signed, the Authorization Request
      # Object SHOULD contain the Claims "iss" (issuer) and "aud" (audience)
      # as members, with their semantics being the same as defined in the JWT
      # [RFC7519] specification.  The value of "aud" should be the value of
      # the Authorization Server (AS) "issuer" as defined in RFC8414
      # [RFC8414].
      claims.delete("iss")
      audience = claims.delete("aud")

      redirect_response_error("invalid_request_object") if audience && audience != issuer

      claims.each do |k, v|
        request.params[k.to_s] = v
      end

      super
    end

    # /token

    def require_oauth_application
      # requset authentication optional for assertions
      return super unless param("grant_type") == "urn:ietf:params:oauth:grant-type:jwt-bearer"

      claims = jwt_decode(param("assertion"))

      redirect_response_error("invalid_grant") unless claims

      @oauth_application = db[oauth_applications_table].where(oauth_applications_client_id_column => claims["client_id"]).first

      authorization_required unless @oauth_application
    end

    def validate_oauth_token_params
      if param("grant_type") == "urn:ietf:params:oauth:grant-type:jwt-bearer"
        redirect_response_error("invalid_client") unless param_or_nil("assertion")
      else
        super
      end
    end

    def create_oauth_token
      if param("grant_type") == "urn:ietf:params:oauth:grant-type:jwt-bearer"
        create_oauth_token_from_assertion
      else
        super
      end
    end

    def create_oauth_token_from_assertion
      claims = jwt_decode(param("assertion"))

      account = account_ds(claims["sub"]).first

      redirect_response_error("invalid_client") unless oauth_application && account

      create_params = {
        oauth_tokens_account_id_column => claims["sub"],
        oauth_tokens_oauth_application_id_column => oauth_application[oauth_applications_id_column],
        oauth_tokens_scopes_column => claims["scope"]
      }

      generate_oauth_token(create_params, false)
    end

    def generate_oauth_token(params = {}, should_generate_refresh_token = true)
      create_params = {
        oauth_grants_expires_in_column => Sequel.date_add(Sequel::CURRENT_TIMESTAMP, seconds: oauth_token_expires_in)
      }.merge(params)

      oauth_token = rescue_from_uniqueness_error do
        if should_generate_refresh_token
          refresh_token = oauth_unique_id_generator

          if oauth_tokens_refresh_token_hash_column
            create_params[oauth_tokens_refresh_token_hash_column] = generate_token_hash(refresh_token)
          else
            create_params[oauth_tokens_refresh_token_column] = refresh_token
          end
        end

        _generate_oauth_token(create_params)
      end

      claims = jwt_claims(oauth_token)

      # one of the points of using jwt is avoiding database lookups, so we put here all relevant
      # token data.
      claims[:scope] = oauth_token[oauth_tokens_scopes_column]

      token = jwt_encode(claims)

      oauth_token[oauth_tokens_token_column] = token
      oauth_token
    end

    def jwt_claims(oauth_token)
      issued_at = Time.now.to_i

      claims = {
        iss: issuer, # issuer
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
        sub: jwt_subject(oauth_token),
        client_id: oauth_application[oauth_applications_client_id_column],

        exp: issued_at + oauth_token_expires_in,
        aud: (oauth_jwt_audience || oauth_application[oauth_applications_client_id_column])
      }

      claims[:auth_time] = last_account_login_at.to_i if last_account_login_at

      claims
    end

    def jwt_subject(oauth_token)
      case oauth_jwt_subject_type
      when "public"
        oauth_token[oauth_tokens_account_id_column]
      when "pairwise"
        id = oauth_token[oauth_tokens_account_id_column]
        application_id = oauth_token[oauth_tokens_oauth_application_id_column]
        Digest::SHA256.hexdigest("#{id}#{application_id}#{oauth_jwt_subject_secret}")
      else
        raise StandardError, "unexpected subject (#{oauth_jwt_subject_type})"
      end
    end

    def oauth_token_by_token(token)
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
        jwks_uri: jwks_url,
        token_endpoint_auth_signing_alg_values_supported: [oauth_jwt_algorithm]
      metadata
    end

    def _jwt_key
      @_jwt_key ||= oauth_jwt_key || (oauth_application[oauth_applications_client_secret_column] if oauth_application)
    end

    # Resource Server only!
    #
    # returns the jwks set from the authorization server.
    def auth_server_jwks_set
      metadata = authorization_server_metadata

      return unless metadata && (jwks_uri = metadata[:jwks_uri])

      jwks_uri = URI(jwks_uri)

      jwks = JWKS[jwks_uri]

      return jwks if jwks

      JWKS.set(jwks_uri) do
        http = Net::HTTP.new(jwks_uri.host, jwks_uri.port)
        http.use_ssl = jwks_uri.scheme == "https"

        request = Net::HTTP::Get.new(jwks_uri.request_uri)
        request["accept"] = json_response_content_type
        response = http.request(request)
        authorization_required unless response.code.to_i == 200

        # time-to-live
        ttl = if response.key?("cache-control")
                cache_control = response["cache-control"]
                cache_control[/max-age=(\d+)/, 1].to_i
              elsif response.key?("expires")
                Time.parse(response["expires"]).to_i - Time.now.to_i
              end

        [JSON.parse(response.body, symbolize_names: true), ttl]
      end
    end

    def generate_jti(iat)
      # Use the key and iat to create a unique key per request to prevent replay attacks
      jti_raw = [hmac_secret, iat].join(":").to_s
      Digest::SHA256.hexdigest(jti_raw)
    end

    def verify_jti(jti, payload)
      generate_jti(payload["iat"]) == jti
    end

    if defined?(JSON::JWT)

      def jwk_import(data)
        JSON::JWK.new(data)
      end

      # json-jwt
      def jwt_encode(payload)
        payload[:jti] = generate_jti(payload[:iat])
        jwt = JSON::JWT.new(payload)
        jwk = JSON::JWK.new(_jwt_key)

        jwt = jwt.sign(jwk, oauth_jwt_algorithm)
        jwt.kid = jwk.thumbprint

        if oauth_jwt_jwe_key
          algorithm = oauth_jwt_jwe_algorithm.to_sym if oauth_jwt_jwe_algorithm
          jwt = jwt.encrypt(oauth_jwt_jwe_public_key || oauth_jwt_jwe_key,
                            algorithm,
                            oauth_jwt_jwe_encryption_method.to_sym)
        end
        jwt.to_s
      end

      def jwt_decode(
        token,
        jws_key: oauth_jwt_public_key || _jwt_key,
        verify: true,
        verify_jti: true,
        **
      )
        token = JSON::JWT.decode(token, oauth_jwt_jwe_key).plain_text if oauth_jwt_jwe_key

        if verify
          claims = if is_authorization_server?
                     if oauth_jwt_legacy_public_key
                       JSON::JWT.decode(token, JSON::JWK::Set.new({ keys: jwks_set }))
                     elsif jws_key
                       JSON::JWT.decode(token, jws_key)
                     end
                   elsif (jwks = auth_server_jwks_set)
                     JSON::JWT.decode(token, JSON::JWK::Set.new(jwks))
                   end

          return unless
            claims[:iss] == issuer &&
            claims[:aud] == (oauth_jwt_audience || oauth_application[oauth_applications_client_id_column]) &&
            (!claims[:iat] || Time.at(claims[:iat]) > (Time.now - oauth_token_expires_in)) &&
            (!claims[:exp] || Time.at(claims[:exp]) > Time.now) &&
            (!verify_jti || verify_jti(claims[:jti], claims))

          claims
        else
          JSON::JWT.decode(token, :skip_verification)
        end
      rescue JSON::JWT::Exception
        nil
      end

      def jwks_set
        @jwks_set ||= [
          (JSON::JWK.new(oauth_jwt_public_key).merge(use: "sig", alg: oauth_jwt_algorithm) if oauth_jwt_public_key),
          (JSON::JWK.new(oauth_jwt_legacy_public_key).merge(use: "sig", alg: oauth_jwt_legacy_algorithm) if oauth_jwt_legacy_public_key),
          (JSON::JWK.new(oauth_jwt_jwe_public_key).merge(use: "enc", alg: oauth_jwt_jwe_algorithm) if oauth_jwt_jwe_public_key)
        ].compact
      end

    elsif defined?(JWT)

      # ruby-jwt

      def jwk_import(data)
        JWT::JWK.import(data).keypair
      end

      def jwt_encode(payload)
        headers = {}

        key = _jwt_key

        if key.is_a?(OpenSSL::PKey::RSA)
          jwk = JWT::JWK.new(_jwt_key)
          headers[:kid] = jwk.kid

          key = jwk.keypair
        end

        # @see JWT reserved claims - https://tools.ietf.org/html/draft-jones-json-web-token-07#page-7
        payload[:jti] = generate_jti(payload[:iat])
        token = JWT.encode(payload, key, oauth_jwt_algorithm, headers)

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

      def jwt_decode(
        token,
        jws_key: oauth_jwt_public_key || _jwt_key,
        jws_algorithm: oauth_jwt_algorithm,
        verify: true,
        verify_jti: true
      )
        # decrypt jwe
        token = JWE.decrypt(token, oauth_jwt_jwe_key) if oauth_jwt_jwe_key

        # verifying the JWT implies verifying:
        #
        # issuer: check that server generated the token
        # aud: check the audience field (client is who he says he is)
        # iat: check that the token didn't expire
        #
        # subject can't be verified automatically without having access to the account id,
        # which we don't because that's the whole point.
        #
        jwt_params = {
          verify_iss: true,
          iss: issuer,
          verify_aud: true,
          aud: (oauth_jwt_audience || oauth_application[oauth_applications_client_id_column]),
          verify_jti: (verify_jti ? method(:verify_jti) : false),
          verify_iat: true
        }

        # decode jwt
        if is_authorization_server?
          if oauth_jwt_legacy_public_key
            algorithms = jwks_set.select { |k| k[:use] == "sig" }.map { |k| k[:alg] }
            JWT.decode(token, nil, verify, jwks: { keys: jwks_set }, algorithms: algorithms, **jwt_params).first
          elsif jws_key
            JWT.decode(token, jws_key, verify, algorithms: [jws_algorithm], **jwt_params).first
          end
        elsif (jwks = auth_server_jwks_set)
          algorithms = jwks[:keys].select { |k| k[:use] == "sig" }.map { |k| k[:alg] }
          JWT.decode(token, nil, verify, jwks: jwks, algorithms: algorithms, **jwt_params).first
        end
      rescue JWT::DecodeError, JWT::JWKError
        nil
      end

      def jwks_set
        @jwks_set ||= [
          (JWT::JWK.new(oauth_jwt_public_key).export.merge(use: "sig", alg: oauth_jwt_algorithm) if oauth_jwt_public_key),
          (
             if oauth_jwt_legacy_public_key
               JWT::JWK.new(oauth_jwt_legacy_public_key).export.merge(use: "sig", alg: oauth_jwt_legacy_algorithm)
             end
           ),
          (JWT::JWK.new(oauth_jwt_jwe_public_key).export.merge(use: "enc", alg: oauth_jwt_jwe_algorithm) if oauth_jwt_jwe_public_key)
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
  end
end
