# frozen_string_literal: true

module Rodauth
  Feature.define(:oauth_authorization_code_grant, :OauthAuthorizationCodeGrant) do
    depends :oauth_base

    before "authorize"
    after "authorize"

    view "authorize", "Authorize", "authorize"

    button "Authorize", "oauth_authorize"
    button "Back to Client Application", "oauth_authorize_post"

    auth_value_method :use_oauth_access_type?, true

    # OAuth Grants
    auth_value_method :oauth_grants_table, :oauth_grants
    auth_value_method :oauth_grants_id_column, :id
    %i[
      account_id oauth_application_id
      redirect_uri code scopes access_type
      expires_in revoked_at
    ].each do |column|
      auth_value_method :"oauth_grants_#{column}_column", column
    end

    translatable_method :oauth_tokens_scopes_label, "Scopes"
    translatable_method :oauth_applications_contacts_label, "Contacts"
    translatable_method :oauth_applications_tos_uri_label, "Terms of service URL"
    translatable_method :oauth_applications_policy_uri_label, "Policy URL"

    # /authorize
    route(:authorize) do |r|
      next unless is_authorization_server?

      before_authorize_route
      require_authorizable_account

      validate_oauth_grant_params
      try_approval_prompt if use_oauth_access_type? && request.get?

      r.get do
        authorize_view
      end

      r.post do
        params, mode = transaction do
          before_authorize
          do_authorize
        end

        authorize_response(params, mode)
      end
    end

    def check_csrf?
      case request.path
      when authorize_path
        only_json? ? false : super
      else
        super
      end
    end

    private

    def validate_oauth_grant_params
      redirect_response_error("invalid_request", request.referer || default_redirect) unless oauth_application && check_valid_redirect_uri?

      unless oauth_application && check_valid_redirect_uri? && check_valid_access_type? &&
             check_valid_approval_prompt? && check_valid_response_type?
        redirect_response_error("invalid_request")
      end
      redirect_response_error("invalid_scope") unless check_valid_scopes?

      return unless (response_mode = param_or_nil("response_mode")) && response_mode != "form_post"

      redirect_response_error("invalid_request")
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
      end

      response_params["state"] = param("state") if param_or_nil("state")

      [response_params, response_mode]
    end

    def _do_authorize_code
      { "code" => create_oauth_grant(oauth_grants_account_id_column => account_id) }
    end

    def authorize_response(params, mode)
      redirect_url = URI.parse(redirect_uri)
      case mode
      when "query"
        params = params.map { |k, v| "#{k}=#{v}" }
        params << redirect_url.query if redirect_url.query
        redirect_url.query = params.join("&")
      when "form_post"
        return scope.view layout: false, inline: <<-FORM
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
      end

      if accepts_json?
        json_response_success("callback_url" => redirect_url.to_s)
      else
        redirect(redirect_url.to_s)
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
      create_oauth_token_from_authorization_code(oauth_grant, create_params)
    end

    def create_oauth_token_from_authorization_code(oauth_grant, create_params)
      # revoke oauth grant
      db[oauth_grants_table].where(oauth_grants_id_column => oauth_grant[oauth_grants_id_column])
                            .update(oauth_grants_revoked_at_column => Sequel::CURRENT_TIMESTAMP)

      should_generate_refresh_token = !use_oauth_access_type? ||
                                      oauth_grant[oauth_grants_access_type_column] == "offline"

      generate_oauth_token(create_params, should_generate_refresh_token)
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

      response_type.nil? || response_type == "code"
    end

    def check_valid_redirect_uri?
      oauth_application[oauth_applications_redirect_uri_column].split(" ").include?(redirect_uri)
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
