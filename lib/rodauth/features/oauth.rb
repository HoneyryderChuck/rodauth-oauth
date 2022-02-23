# frozen-string-literal: true

module Rodauth
  Feature.define(:oauth, :Oauth) do
    depends :oauth_base, :oauth_pkce, :oauth_implicit_grant, :oauth_device_grant, :oauth_token_introspection, :oauth_token_revocation,
            :oauth_application_management, :oauth_token_management
  end
end
