# frozen_string_literal: true

module Rodauth
  Feature.define(:oauth_client_credentials_grant, :OauthClientCredentialsGrant) do
    depends :oauth_base

    auth_value_method :use_oauth_client_credentials_grant_type?, false

    private

    def create_token(grant_type)
      return super unless grant_type == "client_credentials"

      grant_scopes = scopes

      grant_scopes = if grant_scopes
                       grant_scopes.join(oauth_scope_separator)
                     else
                       oauth_application[oauth_applications_scopes_column]
                     end

      grant_params = {
        oauth_grants_oauth_application_id_column => oauth_application[oauth_applications_id_column],
        oauth_grants_scopes_column => grant_scopes
      }
      generate_token(grant_params, false)
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:grant_types_supported] << "client_credentials" if use_oauth_client_credentials_grant_type?
      end
    end

    def check_valid_response_type?
      return true if use_oauth_implicit_grant_type? && param_or_nil("response_type") == "token"

      super
    end
  end
end
