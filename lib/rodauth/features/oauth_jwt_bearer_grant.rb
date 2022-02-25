# frozen-string-literal: true

require "rodauth/oauth/ttl_store"

module Rodauth
  Feature.define(:oauth_jwt_bearer_grant, :OauthJwtBearerGrant) do
    depends :oauth_jwt

    auth_value_method :use_oauth_jwt_bearer_grant_type?, false

    private

    def validate_oauth_token_params
      if use_oauth_jwt_bearer_grant_type? && param("grant_type") == "urn:ietf:params:oauth:grant-type:jwt-bearer"
        redirect_response_error("invalid_client") unless param_or_nil("assertion")
      else
        super
      end
    end

    def create_oauth_token(grant_type)
      if use_oauth_jwt_bearer_grant_type? && grant_type == "urn:ietf:params:oauth:grant-type:jwt-bearer"
        create_oauth_token_from_assertion
      else
        super
      end
    end

    def require_oauth_application
      # requset authentication optional for assertions
      return super unless use_oauth_jwt_bearer_grant_type?

      if (assertion = param_or_nil("assertion"))

        claims = jwt_decode(assertion)

        redirect_response_error("invalid_grant") unless claims

        @oauth_application = db[oauth_applications_table].where(
          oauth_applications_client_id_column => param_or_nil("client_id") || claims["client_id"]
        ).first

        authorization_required unless @oauth_application
      elsif param("client_assertion_type") == "urn:ietf:params:oauth:grant-type:jwt-bearer" &&
            (assertion = param_or_nil("client_assertion"))

        claims = jwt_decode(assertion)

        redirect_response_error("invalid_grant") unless claims

        #  When using assertions for client authentication, the Subject
        # identifies the client to the authorization server using the
        # value of the "client_id" of the OAuth client.
        @oauth_application = db[oauth_applications_table].where(oauth_applications_client_id_column => claims["sub"]).first

        authorization_required unless @oauth_application
      else
        super
      end
    end

    def create_oauth_token_from_assertion
      claims = jwt_decode(param("assertion"))

      account = account_ds(claims["sub"]).first

      redirect_response_error("invalid_client") unless oauth_application && account

      create_params = {
        oauth_tokens_account_id_column => claims["sub"],
        oauth_tokens_oauth_application_id_column => db[oauth_applications_table].where(
          oauth_applications_client_id_column => claims["client_id"]
        ).select(oauth_applications_id_column),
        oauth_tokens_scopes_column => claims["scope"]
      }

      generate_oauth_token(create_params, false)
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:grant_types_supported] << "urn:ietf:params:oauth:grant-type:jwt-bearer" if use_oauth_jwt_bearer_grant_type?
      end
    end
  end
end
