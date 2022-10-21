# frozen_string_literal: true

module Rodauth
  Feature.define(:oauth_client_credentials_grant, :OauthClientCredentialsGrant) do
    depends :oauth_base

    private

    def create_token(grant_type)
      return super unless grant_type == "client_credentials"

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

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:grant_types_supported] << "client_credentials"
      end
    end
  end
end
