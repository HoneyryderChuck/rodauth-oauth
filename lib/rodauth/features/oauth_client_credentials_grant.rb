# frozen_string_literal: true

module Rodauth
  Feature.define(:oauth_client_credentials_grant, :OauthClientCredentialsGrant) do
    depends :oauth_base

    auth_value_method :use_oauth_client_credentials_grant_type?, false

    private

    def create_oauth_token(grant_type)
      return super unless grant_type == "client_credentials" && use_oauth_client_credentials_grant_type?

      create_params = {
        oauth_tokens_oauth_application_id_column => oauth_application[oauth_applications_id_column],
        oauth_tokens_scopes_column => scopes.join(oauth_scope_separator)
      }
      generate_oauth_token(create_params, false)
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
