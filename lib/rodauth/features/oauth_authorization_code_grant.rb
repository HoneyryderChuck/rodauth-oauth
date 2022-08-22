# frozen_string_literal: true

module Rodauth
  Feature.define(:oauth_authorization_code_grant, :OauthAuthorizationCodeGrant) do
    depends :oauth_authorize_base

    auth_value_method :use_oauth_access_type?, true

    private

    def validate_authorize_params
      super

      redirect_response_error("invalid_request") unless check_valid_access_type? && check_valid_approval_prompt?

      redirect_response_error("invalid_request") if (response_mode = param_or_nil("response_mode")) && response_mode != "form_post"

      try_approval_prompt if use_oauth_access_type? && request.get?
    end

    def validate_oauth_token_params
      redirect_response_error("invalid_request") if param_or_nil("grant_type") == "authorization_code" && !param_or_nil("code")
      super
    end

    def try_approval_prompt
      approval_prompt = param_or_nil("approval_prompt")

      return unless approval_prompt && approval_prompt == "auto"

      return if db[oauth_grants_table].where(
        oauth_grants_account_id_column => account_id,
        oauth_grants_oauth_application_id_column => oauth_application[oauth_applications_id_column],
        oauth_grants_redirect_uri_column => redirect_uri,
        oauth_grants_scopes_column => scopes.join(oauth_scope_separator),
        oauth_grants_access_type_column => "online"
      ).count.zero?

      # if there's a previous oauth grant for the params combo, it means that this user has approved before.
      request.env["REQUEST_METHOD"] = "POST"
    end

    def create_oauth_grant(create_params = {})
      create_params.merge!(
        oauth_grants_oauth_application_id_column => oauth_application[oauth_applications_id_column],
        oauth_grants_redirect_uri_column => redirect_uri,
        oauth_grants_expires_in_column => Sequel.date_add(Sequel::CURRENT_TIMESTAMP, seconds: oauth_grant_expires_in),
        oauth_grants_scopes_column => scopes.join(oauth_scope_separator)
      )

      # Access Type flow
      if use_oauth_access_type? && (access_type = param_or_nil("access_type"))
        create_params[oauth_grants_access_type_column] = access_type
      end

      ds = db[oauth_grants_table]

      rescue_from_uniqueness_error do
        create_params[oauth_grants_code_column] = oauth_unique_id_generator
        __insert_and_return__(ds, oauth_grants_id_column, create_params)
      end
      create_params[oauth_grants_code_column]
    end

    def do_authorize(response_params = {}, response_mode = param_or_nil("response_mode"))
      case param("response_type")

      when "code"
        response_mode ||= "query"
        response_params.replace(_do_authorize_code)
      when "none"
        response_mode ||= "none"
      when "", nil
        response_mode ||= oauth_response_mode
        response_params.replace(_do_authorize_code)
      else
        return super if response_params.empty?
      end

      response_params["state"] = param("state") if param_or_nil("state")

      [response_params, response_mode]
    end

    def _do_authorize_code
      create_params = { oauth_grants_account_id_column => account_id }
      # Access Type flow
      if use_oauth_access_type? && (access_type = param_or_nil("access_type"))
        create_params[oauth_grants_access_type_column] = access_type
      end
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
      when "none"
        redirect(redirect_url.to_s)
      else
        super
      end
    end

    def create_oauth_token(grant_type)
      return super unless supported_grant_type?(grant_type, "authorization_code")

      # fetch oauth grant
      oauth_grant = db[oauth_grants_table].where(
        oauth_grants_code_column => param("code"),
        oauth_grants_redirect_uri_column => param("redirect_uri"),
        oauth_grants_oauth_application_id_column => oauth_application[oauth_applications_id_column],
        oauth_grants_revoked_at_column => nil
      ).where(Sequel[oauth_grants_expires_in_column] >= Sequel::CURRENT_TIMESTAMP)
                                          .for_update
                                          .first

      redirect_response_error("invalid_grant") unless oauth_grant

      create_params = {
        oauth_tokens_account_id_column => oauth_grant[oauth_grants_account_id_column],
        oauth_tokens_oauth_application_id_column => oauth_grant[oauth_grants_oauth_application_id_column],
        oauth_tokens_oauth_grant_id_column => oauth_grant[oauth_grants_id_column],
        oauth_tokens_scopes_column => oauth_grant[oauth_grants_scopes_column]
      }
      create_oauth_token_from_authorization_code(oauth_grant, create_params, !use_oauth_access_type?)
    end

    ACCESS_TYPES = %w[offline online].freeze

    def check_valid_access_type?
      return true unless use_oauth_access_type?

      access_type = param_or_nil("access_type")
      !access_type || ACCESS_TYPES.include?(access_type)
    end

    APPROVAL_PROMPTS = %w[force auto].freeze

    def check_valid_approval_prompt?
      return true unless use_oauth_access_type?

      approval_prompt = param_or_nil("approval_prompt")
      !approval_prompt || APPROVAL_PROMPTS.include?(approval_prompt)
    end

    def check_valid_response_type?
      response_type = param_or_nil("response_type")

      response_type.nil? || response_type == "code" || response_type == "none" || super
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:authorization_endpoint] = authorize_url
        data[:response_types_supported] << "code"

        data[:response_modes_supported] << "query"
        data[:response_modes_supported] << "form_post"

        data[:grant_types_supported] << "authorization_code"
      end
    end
  end
end
