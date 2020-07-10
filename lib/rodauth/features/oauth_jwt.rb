# frozen-string-literal: true

require "rodauth/oauth/ttl_store"

module Rodauth
  Feature.define(:oauth_jwt) do
    depends :oauth

    auth_value_method :oauth_jwt_token_issuer, "Example"

    auth_value_method :oauth_application_jws_jwk_column, nil

    auth_value_method :oauth_jwt_key, nil
    auth_value_method :oauth_jwt_public_key, nil
    auth_value_method :oauth_jwt_algorithm, "HS256"

    auth_value_method :oauth_jwt_jwe_key, nil
    auth_value_method :oauth_jwt_jwe_public_key, nil
    auth_value_method :oauth_jwt_jwe_algorithm, nil
    auth_value_method :oauth_jwt_jwe_encryption_method, nil

    auth_value_method :oauth_jwt_jwe_copyright, nil
    auth_value_method :oauth_jwt_audience, nil

    auth_value_method :request_uri_not_supported_message, "request uri is unsupported"
    auth_value_method :invalid_request_object_message, "request object is invalid"

    auth_value_methods(
      :jwt_encode,
      :jwt_decode,
      :jwks_set
    )

    JWKS = OAuth::TtlStore.new

    def require_oauth_authorization(*scopes)
      authorization_required unless authorization_token

      scopes << oauth_application_default_scope if scopes.empty?

      token_scopes = authorization_token["scope"].split(" ")

      authorization_required unless scopes.any? { |scope| token_scopes.include?(scope) }
    end

    private

    def authorization_token
      return @authorization_token if defined?(@authorization_token)

      @authorization_token = begin
        bearer_token = fetch_access_token

        return unless bearer_token

        jwt_token = jwt_decode(bearer_token)

        return unless jwt_token

        return if jwt_token["iss"] != oauth_jwt_token_issuer ||
                  jwt_token["aud"] != oauth_jwt_audience ||
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

                  if jwk
                    jwk = JSON.parse(jwk, symbolize_names: true) if jwk.is_a?(String)
                  end
                else
                  redirect_response_error("invalid_request_object")
                end

      claims = jwt_decode(request_object, jws_key: jwk_import(jws_jwk), jws_algorithm: jwk[:alg])

      redirect_response_error("invalid_request_object") unless claims

      # If signed, the Authorization Request
      # Object SHOULD contain the Claims "iss" (issuer) and "aud" (audience)
      # as members, with their semantics being the same as defined in the JWT
      # [RFC7519] specification.  The value of "aud" should be the value of
      # the Authorization Server (AS) "issuer" as defined in RFC8414
      # [RFC8414].
      claims.delete(:iss)
      audience = claims.delete(:aud)

      redirect_response_error("invalid_request_object") if audience && audience != authorization_server_url

      claims.each do |k, v|
        request.params[k.to_s] = v
      end

      super
    end

    # /token

    def before_token
      # requset authentication optional for assertions
      return if param("grant_type") == "urn:ietf:params:oauth:grant-type:jwt-bearer"

      super
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

      redirect_response_error("invalid_grant") unless claims

      @oauth_application = db[oauth_applications_table].where(oauth_applications_client_id_column => claims["client_id"]).first

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

      claims = jwt_claims(oauth_token)

      # one of the points of using jwt is avoiding database lookups, so we put here all relevant
      # token data.
      claims[:scope] = oauth_token[oauth_tokens_scopes_column]

      token = jwt_encode(claims)

      oauth_token[oauth_tokens_token_column] = token
      oauth_token
    end

    def jwt_claims(oauth_token)
      issued_at = Time.now.utc.to_i

      {
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
        sub: oauth_token[oauth_tokens_account_id_column],
        client_id: oauth_application[oauth_applications_client_id_column],

        exp: issued_at + oauth_token_expires_in,
        aud: oauth_jwt_audience
      }
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
                cache_control = response["cache_control"]
                cache_control[/max-age=(\d+)/, 1]
              elsif response.key?("expires")
                Time.httpdate(response["expires"]).utc.to_i - Time.now.utc.to_i
              end

        [JSON.parse(response.body, symbolize_names: true), ttl]
      end
    end

    if defined?(JSON::JWT)
      # :nocov:

      def jwk_import(data)
        JSON::JWK.new(data)
      end

      # json-jwt
      def jwt_encode(payload)
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

      def jwt_decode(token, jws_key: oauth_jwt_public_key || _jwt_key, **)
        token = JSON::JWT.decode(token, oauth_jwt_jwe_key).plain_text if oauth_jwt_jwe_key

        @jwt_token = if jws_key
                       JSON::JWT.decode(token, jws_key)
                     elsif !is_authorization_server? && auth_server_jwks_set
                       JSON::JWT.decode(token, JSON::JWK::Set.new(auth_server_jwks_set))
                     end
      rescue JSON::JWT::Exception
        nil
      end

      def jwks_set
        [
          (JSON::JWK.new(oauth_jwt_public_key).merge(use: "sig", alg: oauth_jwt_algorithm) if oauth_jwt_public_key),
          (JSON::JWK.new(oauth_jwt_jwe_public_key).merge(use: "enc", alg: oauth_jwt_jwe_algorithm) if oauth_jwt_jwe_public_key)
        ].compact
      end

      # :nocov:
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

        # Use the key and iat to create a unique key per request to prevent replay attacks
        jti_raw = [key, payload[:iat]].join(":").to_s
        jti = Digest::SHA256.hexdigest(jti_raw)

        # @see JWT reserved claims - https://tools.ietf.org/html/draft-jones-json-web-token-07#page-7
        payload[:jti] = jti
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

      def jwt_decode(token, jws_key: oauth_jwt_public_key || _jwt_key, jws_algorithm: oauth_jwt_algorithm)
        # decrypt jwe
        token = JWE.decrypt(token, oauth_jwt_jwe_key) if oauth_jwt_jwe_key

        # decode jwt
        @jwt_token = if jws_key
                       JWT.decode(token, jws_key, true, algorithms: [jws_algorithm]).first
                     elsif !is_authorization_server? && auth_server_jwks_set
                       algorithms = auth_server_jwks_set[:keys].select { |k| k[:use] == "sig" }.map { |k| k[:alg] }
                       JWT.decode(token, nil, true, jwks: auth_server_jwks_set, algorithms: algorithms).first
                     end
      rescue JWT::DecodeError, JWT::JWKError
        nil
      end

      def jwks_set
        [
          (JWT::JWK.new(oauth_jwt_public_key).export.merge(use: "sig", alg: oauth_jwt_algorithm) if oauth_jwt_public_key),
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

    route(:oauth_jwks) do |r|
      r.get do
        json_response_success({ keys: jwks_set })
      end
    end
  end
end
