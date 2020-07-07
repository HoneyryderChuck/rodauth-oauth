# frozen-string-literal: true

module Rodauth
  Feature.define(:oidc) do
    depends :oauth_jwt

    auth_value_method :oauth_application_default_scope, "openid"
    auth_value_method :oauth_application_scopes, %w[openid]
  end
end
