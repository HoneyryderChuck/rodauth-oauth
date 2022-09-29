# frozen_string_literal: true

require "rodauth/oauth"

module Rodauth
  Feature.define(:oauth_resource_server, :OauthResourceServer) do
    depends :oauth_token_introspection

    auth_value_method :is_authorization_server?, false

    def authorization_token
      return @authorization_token if defined?(@authorization_token)

      # check if there is a token
      bearer_token = fetch_access_token

      return unless bearer_token

      # where in resource server, NOT the authorization server.
      payload = introspection_request("access_token", bearer_token)

      return unless payload["active"]

      @authorization_token = payload
    end

    def require_oauth_authorization(*scopes)
      authorization_required unless authorization_token

      aux_scopes = authorization_token["scope"]

      token_scopes = if aux_scopes
                       aux_scopes.split(oauth_scope_separator)
                     else
                       []
                     end

      authorization_required unless scopes.any? { |scope| token_scopes.include?(scope) }
    end
  end
end
