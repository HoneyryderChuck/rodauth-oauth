# frozen_string_literal: true

require "ipaddr"
require "rodauth/oauth"

module Rodauth
  Feature.define(:oauth_authorize_base, :OauthAuthorizeBase) do
    depends :oauth_base

    before "authorize"
    after "authorize"

    view "authorize", "Authorize", "authorize"
    view "authorize_error", "Authorize Error", "authorize_error"

    button "Authorize", "oauth_authorize"
    button "Back to Client Application", "oauth_authorize_post"

    auth_value_method :use_oauth_access_type?, false

    auth_value_method :oauth_grants_access_type_column, :access_type

    translatable_method :authorize_page_lead, "The application %<name>s would like to access your data"
    translatable_method :oauth_grants_scopes_label, "Scopes"
    translatable_method :oauth_applications_contacts_label, "Contacts"
    translatable_method :oauth_applications_tos_uri_label, "Terms of service URL"
    translatable_method :oauth_applications_policy_uri_label, "Policy URL"
    translatable_method :oauth_unsupported_response_type_message, "Unsupported response type"
    translatable_method :oauth_authorize_parameter_required, "Invalid or missing '%<parameter>s'"

    auth_value_methods(
      :resource_owner_params,
      :oauth_grants_resource_owner_columns
    )

    # /authorize
    auth_server_route(:authorize) do |r|
      require_authorizable_account
      before_authorize_route

      validate_authorize_params

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

    def authorize_scopes
      scopes || begin
        oauth_application[oauth_applications_scopes_column].split(oauth_scope_separator)
      end
    end

    private

    def validate_authorize_params
      redirect_authorize_error("client_id") unless oauth_application

      redirect_uris = oauth_application[oauth_applications_redirect_uri_column].split(" ")

      if (redirect_uri = param_or_nil("redirect_uri"))
        normalized_redirect_uri = normalize_redirect_uri_for_comparison(redirect_uri)
        unless redirect_uris.include?(normalized_redirect_uri) || redirect_uris.include?(redirect_uri)
          redirect_authorize_error("redirect_uri")
        end
      elsif redirect_uris.size > 1
        redirect_authorize_error("redirect_uri")
      end

      redirect_response_error("unsupported_response_type") unless check_valid_response_type?

      redirect_response_error("invalid_request") unless check_valid_access_type? && check_valid_approval_prompt?

      try_approval_prompt if use_oauth_access_type? && request.get?

      redirect_response_error("invalid_scope") if (request.post? || param_or_nil("scope")) && !check_valid_scopes?
    end

    def check_valid_scopes?(sc = scopes)
      super(sc - %w[offline_access])
    end

    def check_valid_response_type?
      false
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

    def resource_owner_params
      { oauth_grants_account_id_column => account_id }
    end

    def oauth_grants_resource_owner_columns
      [oauth_grants_account_id_column]
    end

    def try_approval_prompt
      approval_prompt = param_or_nil("approval_prompt")

      return unless approval_prompt && approval_prompt == "auto"

      return if db[oauth_grants_table].where(resource_owner_params).where(
        oauth_grants_oauth_application_id_column => oauth_application[oauth_applications_id_column],
        oauth_grants_redirect_uri_column => redirect_uri,
        oauth_grants_scopes_column => scopes.join(oauth_scope_separator),
        oauth_grants_access_type_column => "online"
      ).count.zero?

      # if there's a previous oauth grant for the params combo, it means that this user has approved before.
      request.env["REQUEST_METHOD"] = "POST"
    end

    def redirect_authorize_error(parameter, referer = request.referer || default_redirect)
      error_message = oauth_authorize_parameter_required(parameter: parameter)

      if accepts_json?
        status_code = oauth_invalid_response_status

        throw_json_response_error(status_code, "invalid_request", error_message)
      else
        scope.instance_variable_set(:@error, error_message)
        scope.instance_variable_set(:@back_url, referer)

        return_response(authorize_error_view)
      end
    end

    def authorization_required
      if accepts_json?
        throw_json_response_error(oauth_authorization_required_error_status, "invalid_client")
      else
        set_redirect_error_flash(require_authorization_error_flash)
        redirect(authorize_path)
      end
    end

    def do_authorize(*args); end

    def authorize_response(params, mode); end

    def create_token_from_authorization_code(grant_params, should_generate_refresh_token = !use_oauth_access_type?, oauth_grant: nil)
      # fetch oauth grant
      oauth_grant ||= valid_locked_oauth_grant(grant_params)

      should_generate_refresh_token ||= oauth_grant[oauth_grants_access_type_column] == "offline"

      generate_token(oauth_grant, should_generate_refresh_token)
    end

    def create_oauth_grant(create_params = {})
      create_params[oauth_grants_oauth_application_id_column] ||= oauth_application[oauth_applications_id_column]
      create_params[oauth_grants_redirect_uri_column] ||= redirect_uri
      create_params[oauth_grants_expires_in_column] ||= Sequel.date_add(Sequel::CURRENT_TIMESTAMP, seconds: oauth_grant_expires_in)
      create_params[oauth_grants_scopes_column] ||= scopes.join(oauth_scope_separator)

      if use_oauth_access_type? && (access_type = param_or_nil("access_type"))
        create_params[oauth_grants_access_type_column] = access_type
      end

      ds = db[oauth_grants_table]

      create_params[oauth_grants_code_column] = oauth_unique_id_generator

      if oauth_reuse_access_token
        unique_conds = Hash[oauth_grants_unique_columns.map { |column| [column, create_params[column]] }]
        valid_grant = valid_oauth_grant_ds(unique_conds).select(oauth_grants_id_column).first
        if valid_grant
          create_params[oauth_grants_id_column] = valid_grant[oauth_grants_id_column]
          rescue_from_uniqueness_error do
            __insert_or_update_and_return__(
              ds,
              oauth_grants_id_column,
              [oauth_grants_id_column],
              create_params
            )
          end
          return create_params[oauth_grants_code_column]
        end
      end

      rescue_from_uniqueness_error do
        if __one_oauth_token_per_account
          __insert_or_update_and_return__(
            ds,
            oauth_grants_id_column,
            oauth_grants_unique_columns,
            create_params,
            nil,
            {
              oauth_grants_expires_in_column => Sequel.date_add(Sequel::CURRENT_TIMESTAMP, seconds: oauth_grant_expires_in),
              oauth_grants_revoked_at_column => nil
            }
          )
        else
          __insert_and_return__(ds, oauth_grants_id_column, create_params)
        end
      end
      create_params[oauth_grants_code_column]
    end

    def normalize_redirect_uri_for_comparison(redirect_uri)
      uri = URI(redirect_uri)

      return redirect_uri unless uri.scheme == "http" && uri.port

      hostname = uri.hostname

      # https://www.rfc-editor.org/rfc/rfc8252#section-7.3
      # ignore (potentially ephemeral) port number for native clients per RFC8252
      begin
        ip = IPAddr.new(hostname)
        uri.port = nil if ip.loopback?
      rescue IPAddr::InvalidAddressError
        # https://www.rfc-editor.org/rfc/rfc8252#section-8.3
        # Although the use of localhost is NOT RECOMMENDED, it is still allowed.
        uri.port = nil if hostname == "localhost"
      end

      uri.to_s
    end
  end
end
