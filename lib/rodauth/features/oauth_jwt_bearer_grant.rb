# frozen-string-literal: true

require "rodauth/oauth/ttl_store"

module Rodauth
  Feature.define(:oauth_jwt_bearer_grant, :OauthJwtBearerGrant) do
    depends :oauth_jwt

    private

    def require_oauth_application
      grant_type = param("grant_type")

      return if grant_type == "urn:ietf:params:oauth:grant-type:jwt-bearer"

      unless param("client_assertion_type") == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" &&
             (assertion = param_or_nil("client_assertion"))
        return super
      end

      claims = jwt_assertion(assertion)

      redirect_response_error("invalid_grant") unless claims

      # For client authentication, the Subject MUST be the "client_id" of the OAuth client.
      @oauth_application = db[oauth_applications_table].where(
        oauth_applications_client_id_column => claims["sub"]
      ).first

      redirect_response_error("invalid_grant") unless @oauth_application
    end

    def jwt_assertion(assertion)
      claims = jwt_decode(assertion, verify_iss: false, verify_aud: false)
      return unless verify_aud(token_url, claims["aud"])

      claims
    end

    def validate_oauth_token_params
      return super unless param("grant_type") == "urn:ietf:params:oauth:grant-type:jwt-bearer"

      redirect_response_error("invalid_grant") unless param_or_nil("assertion")
    end

    def create_oauth_token(grant_type)
      if grant_type == "urn:ietf:params:oauth:grant-type:jwt-bearer"
        create_oauth_token_from_assertion
      else
        super
      end
    end

    def create_oauth_token_from_assertion
      claims = jwt_assertion(param("assertion"))
      redirect_response_error("invalid_grant") unless claims

      # claims = jwt_decode(param("assertion"))

      account = db[accounts_table].where(login_column => claims["sub"]).first

      redirect_response_error("invalid_grant") unless account

      @oauth_application = db[oauth_applications_table].where(
        oauth_applications_client_id_column => claims["iss"]
      ).first

      redirect_response_error("invalid_grant") unless @oauth_application

      grant_scopes = if param_or_nil("scope")
                       redirect_response_error("invalid_grant") unless check_valid_scopes?
                       scopes
                     else
                       @oauth_application[oauth_applications_scopes_column]
                     end

      create_params = {
        oauth_tokens_account_id_column => account[account_id_column],
        oauth_tokens_oauth_application_id_column => @oauth_application[oauth_applications_id_column],
        oauth_tokens_scopes_column => grant_scopes
      }

      generate_oauth_token(create_params, false)
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:grant_types_supported] << "urn:ietf:params:oauth:grant-type:jwt-bearer"
      end
    end
  end
end
