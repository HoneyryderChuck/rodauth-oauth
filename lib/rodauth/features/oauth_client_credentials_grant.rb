# frozen_string_literal: true

module Rodauth
  Feature.define(:oauth_client_credentials_grant, :OauthClientCredentialsGrant) do
    depends :oauth_base

    def oauth_grant_types_supported
      super | %w[client_credentials]
    end

    private

    def create_token(grant_type)
      return super unless supported_grant_type?(grant_type, "client_credentials")

      grant_scopes = scopes

      grant_scopes = if grant_scopes
                       redirect_response_error("invalid_scope") unless check_valid_scopes?
                       grant_scopes.join(oauth_scope_separator)
                     else
                       oauth_application[oauth_applications_scopes_column]
                     end

      grant_params = {
        oauth_grants_type_column => "client_credentials",
        oauth_grants_oauth_application_id_column => oauth_application[oauth_applications_id_column],
        oauth_grants_scopes_column => grant_scopes
      }
      generate_token(grant_params, false)
    end
  end
end
