# frozen_string_literal: true

require "rodauth/oauth"

module Rodauth
  Feature.define(:oauth_resource_server, :OauthResourceServer) do
    depends :oauth_token_introspection

    auth_value_method :is_authorization_server?, false

    auth_value_methods(
      :before_introspection_request
    )

    def authorization_token
      return @authorization_token if defined?(@authorization_token)

      # check if there is a token
      access_token = fetch_access_token

      return unless access_token

      # where in resource server, NOT the authorization server.
      payload = introspection_request("access_token", access_token)

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

    private

    def introspection_request(token_type_hint, token)
      introspect_url = URI("#{authorization_server_url}#{introspect_path}")

      response = http_request(introspect_url, { "token_type_hint" => token_type_hint, "token" => token }) do |request|
        before_introspection_request(request)
      end

      JSON.parse(response.body)
    end

    def before_introspection_request(request); end
  end
end
