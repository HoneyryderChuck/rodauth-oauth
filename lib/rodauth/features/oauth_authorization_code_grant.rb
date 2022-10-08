# frozen_string_literal: true

require "rodauth/oauth"

module Rodauth
  Feature.define(:oauth_authorization_code_grant, :OauthAuthorizationCodeGrant) do
    depends :oauth_authorize_base

    def oauth_grant_types_supported
      super | %w[authorization_code]
    end

    def oauth_response_types_supported
      super | %w[code]
    end

    def oauth_response_modes_supported
      super | %w[query form_post]
    end

    private

    def validate_authorize_params
      super

      redirect_response_error("invalid_request") if (response_mode = param_or_nil("response_mode")) && response_mode != "form_post"
    end

    def validate_token_params
      redirect_response_error("invalid_request") if param_or_nil("grant_type") == "authorization_code" && !param_or_nil("code")
      super
    end

    def do_authorize(response_params = {}, response_mode = param_or_nil("response_mode"))
      response_mode ||= oauth_response_mode

      redirect_response_error("invalid_request") unless response_mode.nil? || supported_response_mode?(response_mode)

      response_type = param_or_nil("response_type")

      redirect_response_error("invalid_request") unless response_type.nil? || supported_response_type?(response_type)

      case response_type
      when "code", nil
        response_mode ||= "query"
        response_params.replace(_do_authorize_code)
      end

      response_params["state"] = param("state") if param_or_nil("state")

      [response_params, response_mode]
    end

    def _do_authorize_code
      create_params = {
        oauth_grants_type_column => "authorization_code",
        oauth_grants_account_id_column => account_id
      }

      { "code" => create_oauth_grant(create_params) }
    end

    def authorize_response(params, mode)
      redirect_url = URI.parse(redirect_uri)
      case mode
      when "query"
        params = params.map { |k, v| "#{k}=#{v}" }
        params << redirect_url.query if redirect_url.query
        redirect_url.query = params.join("&")
        redirect(redirect_url.to_s)
      when "form_post"
        scope.view layout: false, inline: <<-FORM
          <html>
            <head><title>Authorized</title></head>
            <body onload="javascript:document.forms[0].submit()">
              <form method="post" action="#{redirect_uri}">
                #{
                  params.map do |name, value|
                    "<input type=\"hidden\" name=\"#{name}\" value=\"#{scope.h(value)}\" />"
                  end.join
                }
                <input type="submit" class="btn btn-outline-primary" value="#{scope.h(oauth_authorize_post_button)}"/>
              </form>
            </body>
          </html>
        FORM
      end
    end

    def create_token(grant_type)
      return super unless supported_grant_type?(grant_type, "authorization_code")

      grant_params = {
        oauth_grants_type_column => grant_type,
        oauth_grants_code_column => param("code"),
        oauth_grants_redirect_uri_column => param("redirect_uri"),
        oauth_grants_oauth_application_id_column => oauth_application[oauth_applications_id_column]
      }

      create_token_from_authorization_code(grant_params)
    end

    def check_valid_response_type?
      response_type = param_or_nil("response_type")

      response_type.nil? || response_type == "code" || response_type == "none" || super
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:authorization_endpoint] = authorize_url
      end
    end
  end
end
