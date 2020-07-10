# frozen-string-literal: true

module Rodauth
  Feature.define(:oidc) do
    depends :oauth_jwt

    auth_value_method :oauth_application_default_scope, "openid"
    auth_value_method :oauth_application_scopes, %w[openid]

    auth_value_method :oauth_grants_nonce_column, :nonce
    auth_value_method :oauth_tokens_nonce_column, :nonce

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

      return oauth_token unless oauth_token[oauth_tokens_scopes_column].split(oauth_scope_separator).include?("openid")

      id_token_claims = jwt_claims(oauth_token)
      id_token_claims[:nonce] = oauth_token[oauth_tokens_nonce_column] if oauth_token[oauth_tokens_nonce_column]

      # Time when the End-User authentication occurred.
      #
      # Sounds like the same as issued at claim.
      id_token_claims[:auth_time] = id_token_claims[:iat]

      oauth_token[:id_token] = jwt_encode(id_token_claims)

      oauth_token
    end

    def json_access_token_payload(oauth_token)
      payload = super
      payload["id_token"] = oauth_token[:id_token] if oauth_token[:id_token]
      payload
    end
  end
end
