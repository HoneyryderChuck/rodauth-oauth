# frozen_string_literal: true

module Rodauth
  Feature.define(:oauth_authorize_base, :OauthAuthorizeBase) do
    depends :oauth_base

    before "authorize"
    after "authorize"

    view "authorize", "Authorize", "authorize"

    button "Authorize", "oauth_authorize"
    button "Back to Client Application", "oauth_authorize_post"

    translatable_method :oauth_grants_scopes_label, "Scopes"
    translatable_method :oauth_applications_contacts_label, "Contacts"
    translatable_method :oauth_applications_tos_uri_label, "Terms of service URL"
    translatable_method :oauth_applications_policy_uri_label, "Policy URL"

    # /authorize
    auth_server_route(:authorize) do |r|
      before_authorize_route
      require_authorizable_account

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
      redirect_response_error("invalid_request", request.referer || default_redirect) unless oauth_application && check_valid_redirect_uri?

      redirect_response_error("invalid_request") unless check_valid_response_type?

      redirect_response_error("invalid_scope") if (request.post? || param_or_nil("scope")) && !check_valid_scopes?
    end

    def check_valid_response_type?
      false
    end

    def check_valid_redirect_uri?
      oauth_application[oauth_applications_redirect_uri_column].split(" ").include?(redirect_uri)
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

    def create_token_from_authorization_code(grant_params, should_generate_refresh_token = false, oauth_grant: nil)
      # fetch oauth grant
      oauth_grant ||= valid_locked_oauth_grant(grant_params)

      should_generate_refresh_token ||= oauth_grant[oauth_grants_access_type_column] == "offline"

      generate_token(oauth_grant, should_generate_refresh_token)
    end

    def create_oauth_grant(create_params = {})
      create_params.merge!(
        oauth_grants_oauth_application_id_column => oauth_application[oauth_applications_id_column],
        oauth_grants_redirect_uri_column => redirect_uri,
        oauth_grants_expires_in_column => Sequel.date_add(Sequel::CURRENT_TIMESTAMP, seconds: oauth_grant_expires_in),
        oauth_grants_scopes_column => scopes.join(oauth_scope_separator)
      )

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
  end
end
