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

    auth_value_methods(:get_oidc_param)

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

      oidc_scopes = (OIDC_SCOPES_MAP.keys & oauth_scopes)

      unless oidc_scopes.empty?
        if respond_to?(:get_oidc_param)
          oidc_scopes.each do |scope|
            OIDC_SCOPES_MAP[scope].each do |param|
              id_token_claims[param] = __send__(:get_oidc_param, oauth_token, param)
            end
          end
        else
          warn "`get_oidc_param(token, param)` must be implemented to use oidc scopes."
        end
      end

      oauth_token[:id_token] = jwt_encode(id_token_claims)
    end

    def json_access_token_payload(oauth_token)
      payload = super
      payload["id_token"] = oauth_token[:id_token] if oauth_token[:id_token]
      payload
    end

    # Authorize

    def check_valid_response_type?
      case param_or_nil("response_type")
      when "none", "id_token"
        true
      else
        super
      end
    end

    def do_authorize(redirect_url, query_params = [], fragment_params = [])
      case param("response_type")
      when "id_token"
        create_params = {
          oauth_tokens_account_id_column => account_id,
          oauth_tokens_oauth_application_id_column => oauth_application[oauth_applications_id_column],
          oauth_tokens_scopes_column => scopes
        }
        oauth_token = generate_oauth_token(create_params, false)
        generate_id_token(oauth_token)
        params = json_access_token_payload(oauth_token)
        params.delete("access_token")

        fragment_params.replace(params.map { |k, v| "#{k}=#{v}" })
      end

      super(redirect_url, query_params, fragment_params)
    end
  end
end
