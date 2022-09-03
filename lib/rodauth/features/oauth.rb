# frozen_string_literal: true

module Rodauth
  Feature.define(:oauth, :Oauth) do
    depends :oauth_base, :oauth_authorization_code_grant, :oauth_pkce, :oauth_implicit_grant,
            :oauth_client_credentials_grant, :oauth_device_grant, :oauth_token_introspection,
            :oauth_token_revocation, :oauth_application_management, :oauth_grant_management
  end
end
