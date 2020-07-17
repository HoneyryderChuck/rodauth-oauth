# frozen-string-literal: true

module Rodauth
  Feature.define(:oidc) do
    OIDC_SCOPES_MAP = {
      "profile" => %i[name family_name given_name middle_name nickname preferred_username
                      profile picture website gender birthdate zoneinfo locale updated_at].freeze,
      "email" => %i[email email_verified].freeze,
      "address" => %i[address].freeze,
      "phone" => %i[phone_number phone_number_verified].freeze
    }.freeze

    depends :oauth_jwt

    auth_value_method :oauth_application_default_scope, "openid"
    auth_value_method :oauth_application_scopes, %w[openid]

    auth_value_method :oauth_grants_nonce_column, :nonce
    auth_value_method :oauth_tokens_nonce_column, :nonce

    auth_value_method :invalid_scope_message, "The Access Token expired"

    auth_value_methods(:get_oidc_param)

    def openid_configuration(issuer = nil)
      request.on(".well-known") do
        request.on("openid-configuration") do
          request.get do
            json_response_success(openid_configuration_body(issuer))
          end
        end
      end
    end

    private

    def create_oauth_grant(create_params = {})
      return super unless (nonce = param_or_nil("nonce"))

      super(oauth_grants_nonce_column => nonce)
    end

    def create_oauth_token_from_authorization_code(oauth_grant, create_params)
      return super unless oauth_grant[oauth_grants_nonce_column]

      super(oauth_grant, create_params.merge(oauth_tokens_nonce_column => oauth_grant[oauth_grants_nonce_column]))
    end

    def create_oauth_token
      oauth_token = super
      generate_id_token(oauth_token)
      oauth_token
    end

    def generate_id_token(oauth_token)
      oauth_scopes = oauth_token[oauth_tokens_scopes_column].split(oauth_scope_separator)

      return unless oauth_scopes.include?("openid")

      id_token_claims = jwt_claims(oauth_token)
      id_token_claims[:nonce] = oauth_token[oauth_tokens_nonce_column] if oauth_token[oauth_tokens_nonce_column]

      # Time when the End-User authentication occurred.
      #
      # Sounds like the same as issued at claim.
      id_token_claims[:auth_time] = id_token_claims[:iat]

      fill_with_user_claims(id_token_claims, oauth_token, oauth_scopes)

      oauth_token[:id_token] = jwt_encode(id_token_claims)
    end

    def fill_with_user_claims(claims, oauth_token, scopes)
      scopes_by_oidc = scopes.each_with_object({}) do |scope, by_oidc|
        oidc, param = scope.split(".", 2)

        by_oidc[oidc] ||= []

        by_oidc[oidc] << param.to_sym if param
      end

      oidc_scopes = (OIDC_SCOPES_MAP.keys & scopes_by_oidc.keys)

      return if oidc_scopes.empty?

      if respond_to?(:get_oidc_param)
        oidc_scopes.each do |scope|
          params = scopes_by_oidc[scope]
          params = params.empty? ? OIDC_SCOPES_MAP[scope] : (OIDC_SCOPES_MAP[scope] & params)

          params.each do |param|
            claims[param] = __send__(:get_oidc_param, oauth_token, param)
          end
        end
      else
        warn "`get_oidc_param(token, param)` must be implemented to use oidc scopes."
      end
    end

    def json_access_token_payload(oauth_token)
      payload = super
      payload["id_token"] = oauth_token[:id_token] if oauth_token[:id_token]
      payload
    end

    # Authorize

    def check_valid_response_type?
      case param_or_nil("response_type")
      when "none", "id_token",
           "code token", "code id_token", "id_token token", "code id_token token" # multiple
        true
      else
        super
      end
    end

    def do_authorize(redirect_url, query_params = [], fragment_params = [])
      case param("response_type")
      when "id_token"
        fragment_params.replace(_do_authorize_id_token.map { |k, v| "#{k}=#{v}" })
      when "code token"
        redirect_response_error("invalid_request") unless use_oauth_implicit_grant_type?

        params = _do_authorize_code.merge(_do_authorize_token)

        fragment_params.replace(params.map { |k, v| "#{k}=#{v}" })
      when "code id_token"
        params = _do_authorize_code.merge(_do_authorize_id_token)

        fragment_params.replace(params.map { |k, v| "#{k}=#{v}" })
      when "id_token token"
        params = _do_authorize_id_token.merge(_do_authorize_token)

        fragment_params.replace(params.map { |k, v| "#{k}=#{v}" })
      when "code id_token token"
        params = _do_authorize_code.merge(_do_authorize_id_token).merge(_do_authorize_token)

        fragment_params.replace(params.map { |k, v| "#{k}=#{v}" })
      end

      super(redirect_url, query_params, fragment_params)
    end

    def _do_authorize_id_token
      create_params = {
        oauth_tokens_account_id_column => account_id,
        oauth_tokens_oauth_application_id_column => oauth_application[oauth_applications_id_column],
        oauth_tokens_scopes_column => scopes
      }
      oauth_token = generate_oauth_token(create_params, false)
      generate_id_token(oauth_token)
      params = json_access_token_payload(oauth_token)
      params.delete("access_token")
      params
    end

    # Metadata

    def openid_configuration_body(path)
      metadata = oauth_server_metadata_body(path)

      scope_claims = oauth_application_scopes.each_with_object([]) do |scope, claims|
        oidc, param = scope.split(".", 2)
        if param
          claims << param
        else
          oidc_claims = OIDC_SCOPES_MAP[oidc]
          claims.concat(oidc_claims) if oidc_claims
        end
      end

      scope_claims.unshift("auth_time") if last_account_login_at

      metadata.merge({
                       userinfo_endpoint: userinfo_url,
                       response_types_supported: metadata[:response_types_supported] +
                         ["none", "id_token", %w[code token], %w[code id_token], %w[id_token token], %w[code id_token token]],
                       response_modes_supported: %w[query fragment],
                       grant_types_supported: %w[authorization_code implicit],

                       id_token_signing_alg_values_supported: metadata[:token_endpoint_auth_signing_alg_values_supported],
                       id_token_encryption_alg_values_supported: [oauth_jwt_jwe_algorithm].compact,
                       id_token_encryption_enc_values_supported: [oauth_jwt_jwe_encryption_method].compact,

                       userinfo_signing_alg_values_supported: [],
                       userinfo_encryption_alg_values_supported: [],
                       userinfo_encryption_enc_values_supported: [],

                       request_object_signing_alg_values_supported: [],
                       request_object_encryption_alg_values_supported: [],
                       request_object_encryption_enc_values_supported: [],

                       # These Claim Types are described in Section 5.6 of OpenID Connect Core 1.0 [OpenID.Core].
                       # Values defined by this specification are normal, aggregated, and distributed.
                       # If omitted, the implementation supports only normal Claims.
                       claim_types_supported: %w[normal],
                       claims_supported: %w[sub iss iat exp aud] | scope_claims
                     })
    end

    # /userinfo
    route(:userinfo) do |r|
      r.on method: %i[get post] do
        catch_error do
          oauth_token = authorization_token

          redirect_response_error("invalid_token") unless oauth_token

          oauth_scopes = oauth_token["scope"].split(" ")

          throw_json_response_error(authorization_required_error_status, "invalid_token") unless oauth_scopes.include?("openid")

          oauth_scopes.delete("openid")

          oidc_claims = { "sub" => oauth_token["sub"] }

          fill_with_user_claims(oidc_claims, oauth_token, oauth_scopes)

          json_response_success(oidc_claims)
        end

        throw_json_response_error(authorization_required_error_status, "invalid_token")
      end
    end
  end
end
