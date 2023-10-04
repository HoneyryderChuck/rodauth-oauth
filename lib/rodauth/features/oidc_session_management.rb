# frozen_string_literal: true

require "rodauth/oauth"

module Rodauth
  Feature.define(:oidc_session_management, :OidcSessionManagement) do
    depends :oidc

    view "check_session", "Check Session", "check_session"

    auth_value_method :oauth_oidc_user_agent_state_cookie_key, "_rodauth_oauth_user_agent_state"
    auth_value_method :oauth_oidc_user_agent_state_cookie_options, {}.freeze
    auth_value_method :oauth_oidc_user_agent_state_cookie_expires_in, 365 * 24 * 60 * 60 # 1 year

    auth_value_method :oauth_oidc_user_agent_state_js, nil

    auth_value_methods(
      :oauth_oidc_session_management_salt
    )
    # /authorize
    auth_server_route(:check_session) do |r|
      allow_cors(r)

      r.get do
        set_title(:check_session_page_title)
        scope.view(_view_opts("check_session").merge(layout: false))
      end
    end

    def clear_session
      super

      # update user agent state in the process
      # TODO: dangerous if this gets overidden by the user

      user_agent_state_cookie_opts = Hash[oauth_oidc_user_agent_state_cookie_options]
      user_agent_state_cookie_opts[:value] = oauth_unique_id_generator
      user_agent_state_cookie_opts[:expires] = convert_timestamp(Time.now + oauth_oidc_user_agent_state_cookie_expires_in)
      user_agent_state_cookie_opts[:secure] = true
      ::Rack::Utils.set_cookie_header!(response.headers, oauth_oidc_user_agent_state_cookie_key, user_agent_state_cookie_opts)
    end

    private

    def do_authorize(*)
      params, mode = super

      params["session_state"] = generate_session_state

      [params, mode]
    end

    def response_error_params(*)
      payload = super

      return payload unless request.path == authorize_path

      payload["session_state"] = generate_session_state
      payload
    end

    def generate_session_state
      salt = oauth_oidc_session_management_salt

      uri = URI(redirect_uri)
      origin = if uri.respond_to?(:origin)
                 uri.origin
               else
                 # TODO: remove when not supporting uri < 0.11
                 "#{uri.scheme}://#{uri.host}#{":#{uri.port}" if uri.port != uri.default_port}"
               end
      session_id = "#{oauth_application[oauth_applications_client_id_column]} " \
                   "#{origin} " \
                   "#{request.cookies[oauth_oidc_user_agent_state_cookie_key]} #{salt}"

      "#{Digest::SHA256.hexdigest(session_id)}.#{salt}"
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:check_session_iframe] = check_session_url
      end
    end

    def oauth_oidc_session_management_salt
      oauth_unique_id_generator
    end
  end
end
