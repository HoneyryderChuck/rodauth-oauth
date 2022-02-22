# frozen_string_literal: true

module Rodauth
  Feature.define(:oauth_implicit_grant, :OauthImplicitGrant) do
    depends :oauth_base

    auth_value_method :use_oauth_implicit_grant_type?, false

    private

    def do_authorize(response_params = {}, response_mode = param_or_nil("response_mode"))
      return super unless param("response_type") == "token" && use_oauth_implicit_grant_type?

      response_mode ||= "fragment"
      response_params.replace(_do_authorize_token)

      response_params["state"] = param("state") if param_or_nil("state")

      [response_params, response_mode]
    end

    def _do_authorize_token
      create_params = {
        oauth_tokens_account_id_column => account_id,
        oauth_tokens_oauth_application_id_column => oauth_application[oauth_applications_id_column],
        oauth_tokens_scopes_column => scopes
      }
      oauth_token = generate_oauth_token(create_params, false)

      json_access_token_payload(oauth_token)
    end

    def authorize_response(params, mode)
      return super unless mode == "fragment"

      redirect_url = URI.parse(redirect_uri)
      params = params.map { |k, v| "#{k}=#{v}" }
      params << redirect_url.query if redirect_url.query
      redirect_url.fragment = params.join("&")
      redirect(redirect_url.to_s)
    end

    def check_valid_response_type?
      return true if use_oauth_implicit_grant_type? && param_or_nil("response_type") == "token"

      super
    end
  end
end
