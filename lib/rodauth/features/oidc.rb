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
  end
end
