# frozen_string_literal: true

require "rodauth/oauth"

module Rodauth
  Feature.define(:oauth_implicit_grant, :OauthImplicitGrant) do
    depends :oauth_authorize_base

    def oauth_grant_types_supported
      super | %w[implicit]
    end

    def oauth_response_types_supported
      super | %w[token]
    end

    def oauth_response_modes_supported
      super | %w[fragment]
    end

    private

    def validate_authorize_params
      super

      response_mode = param_or_nil("response_mode")

      return unless response_mode

      response_type = param_or_nil("response_type")

      return unless response_type == "token"

      redirect_response_error("invalid_request") unless oauth_response_modes_for_token_supported.include?(response_mode)
    end

    def oauth_response_modes_for_token_supported
      %w[fragment]
    end

    def do_authorize(response_params = {}, response_mode = param_or_nil("response_mode"))
      response_type = param("response_type")
      return super unless response_type == "token" && supported_response_type?(response_type)

      response_mode ||= "fragment"

      redirect_response_error("invalid_request") unless supported_response_mode?(response_mode)

      oauth_grant = _do_authorize_token

      response_params.replace(json_access_token_payload(oauth_grant))

      response_params["state"] = param("state") if param_or_nil("state")

      [response_params, response_mode]
    end

    def _do_authorize_token(grant_params = {})
      grant_params = {
        oauth_grants_type_column => "implicit",
        oauth_grants_oauth_application_id_column => oauth_application[oauth_applications_id_column],
        oauth_grants_scopes_column => scopes,
        **resource_owner_params
      }.merge(grant_params)

      generate_token(grant_params, false)
    end

    def _redirect_response_error(redirect_url, params)
      response_types = param("response_type").split(/ +/)

      return super if response_types.empty? || response_types == %w[code]

      params = params.map { |k, v| "#{k}=#{v}" }
      redirect_url.fragment = params.join("&")
      redirect(redirect_url.to_s)
    end

    def authorize_response(params, mode)
      return super unless mode == "fragment"

      redirect_url = URI.parse(redirect_uri)
      params = [URI.encode_www_form(params)]
      params << redirect_url.query if redirect_url.query
      redirect_url.fragment = params.join("&")
      redirect(redirect_url.to_s)
    end

    def check_valid_response_type?
      return true if param_or_nil("response_type") == "token"

      super
    end
  end
end
