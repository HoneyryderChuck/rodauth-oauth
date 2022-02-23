# frozen_string_literal: true

module Rodauth
  Feature.define(:oauth_application_management, :OauthApplicationManagement) do
    depends :oauth_base

    before "create_oauth_application"
    after "create_oauth_application"

    error_flash "There was an error registering your oauth application", "create_oauth_application"
    notice_flash "Your oauth application has been registered", "create_oauth_application"

    view "oauth_applications", "Oauth Applications", "oauth_applications"
    view "oauth_application", "Oauth Application", "oauth_application"
    view "new_oauth_application", "New Oauth Application", "new_oauth_application"
    view "oauth_application_oauth_tokens", "Oauth Application Tokens", "oauth_application_oauth_tokens"

    auth_value_method :oauth_valid_uri_schemes, %w[https]

    # Application
    APPLICATION_REQUIRED_PARAMS = %w[name description scopes homepage_url redirect_uri client_secret].freeze
    auth_value_method :oauth_application_required_params, APPLICATION_REQUIRED_PARAMS

    (APPLICATION_REQUIRED_PARAMS + %w[client_id]).each do |param|
      auth_value_method :"oauth_application_#{param}_param", param
      configuration_module_eval do
        define_method :"#{param}_label" do
          warn "#{__method__} is deprecated, switch to oauth_applications_#{__method__}"
          before_otp_auth_route(&block)
        end
      end
    end

    translatable_method :oauth_applications_name_label, "Name"
    translatable_method :oauth_applications_description_label, "Description"
    translatable_method :oauth_applications_scopes_label, "Scopes"
    translatable_method :oauth_applications_homepage_url_label, "Homepage URL"
    translatable_method :oauth_applications_redirect_uri_label, "Redirect URI"
    translatable_method :oauth_applications_client_secret_label, "Client Secret"
    translatable_method :oauth_applications_client_id_label, "Client ID"
    button "Register", "oauth_application"
    button "Revoke", "oauth_token_revoke"

    auth_value_method :oauth_applications_oauth_tokens_path, "oauth-tokens"
    auth_value_method :oauth_applications_route, "oauth-applications"
    auth_value_method :oauth_applications_id_pattern, Integer

    translatable_method :invalid_url_message, "Invalid URL"
    translatable_method :null_error_message, "is not filled"

    def oauth_applications_path(opts = {})
      route_path(oauth_applications_route, opts)
    end

    def oauth_applications_url(opts = {})
      route_url(oauth_applications_route, opts)
    end
    auth_value_methods(
      :oauth_application_path
    )

    def oauth_application_path(id)
      "#{oauth_applications_path}/#{id}"
    end

    # /oauth-applications routes
    def oauth_applications
      request.on(oauth_applications_route) do
        require_account

        request.get "new" do
          new_oauth_application_view
        end

        request.on(oauth_applications_id_pattern) do |id|
          oauth_application = db[oauth_applications_table]
                              .where(oauth_applications_id_column => id)
                              .where(oauth_applications_account_id_column => account_id)
                              .first
          next unless oauth_application

          scope.instance_variable_set(:@oauth_application, oauth_application)

          request.is do
            request.get do
              oauth_application_view
            end
          end

          request.on(oauth_applications_oauth_tokens_path) do
            oauth_tokens = db[oauth_tokens_table].where(oauth_tokens_oauth_application_id_column => id)
            scope.instance_variable_set(:@oauth_tokens, oauth_tokens)
            request.get do
              oauth_application_oauth_tokens_view
            end
          end
        end

        request.get do
          scope.instance_variable_set(:@oauth_applications, db[oauth_applications_table]
            .where(oauth_applications_account_id_column => account_id))
          oauth_applications_view
        end

        request.post do
          catch_error do
            validate_oauth_application_params

            transaction do
              before_create_oauth_application
              id = create_oauth_application
              after_create_oauth_application
              set_notice_flash create_oauth_application_notice_flash
              redirect "#{request.path}/#{id}"
            end
          end
          set_error_flash create_oauth_application_error_flash
          new_oauth_application_view
        end
      end
    end

    def check_csrf?
      case request.path
      when oauth_applications_path
        only_json? ? false : super
      else
        super
      end
    end

    private

    def oauth_application_params
      @oauth_application_params ||= oauth_application_required_params.each_with_object({}) do |param, params|
        value = request.params[__send__(:"oauth_application_#{param}_param")]
        if value && !value.empty?
          params[param] = value
        else
          set_field_error(param, null_error_message)
        end
      end
    end

    def validate_oauth_application_params
      oauth_application_params.each do |key, value|
        if key == oauth_application_homepage_url_param

          set_field_error(key, invalid_url_message) unless check_valid_uri?(value)

        elsif key == oauth_application_redirect_uri_param

          if value.respond_to?(:each)
            value.each do |uri|
              next if uri.empty?

              set_field_error(key, invalid_url_message) unless check_valid_uri?(uri)
            end
          else
            set_field_error(key, invalid_url_message) unless check_valid_uri?(value)
          end
        elsif key == oauth_application_scopes_param

          value.each do |scope|
            set_field_error(key, invalid_scope_message) unless oauth_application_scopes.include?(scope)
          end
        end
      end

      throw :rodauth_error if @field_errors && !@field_errors.empty?
    end

    def create_oauth_application
      create_params = {
        oauth_applications_account_id_column => account_id,
        oauth_applications_name_column => oauth_application_params[oauth_application_name_param],
        oauth_applications_description_column => oauth_application_params[oauth_application_description_param],
        oauth_applications_scopes_column => oauth_application_params[oauth_application_scopes_param],
        oauth_applications_homepage_url_column => oauth_application_params[oauth_application_homepage_url_param]
      }

      redirect_uris = oauth_application_params[oauth_application_redirect_uri_param]
      redirect_uris = redirect_uris.to_a.reject(&:empty?).join(" ") if redirect_uris.respond_to?(:each)
      create_params[oauth_applications_redirect_uri_column] = redirect_uris unless redirect_uris.empty?
      # set client ID/secret pairs

      create_params.merge! \
        oauth_applications_client_secret_column => \
          secret_hash(oauth_application_params[oauth_application_client_secret_param])

      create_params[oauth_applications_scopes_column] = if create_params[oauth_applications_scopes_column]
                                                          create_params[oauth_applications_scopes_column].join(oauth_scope_separator)
                                                        else
                                                          oauth_application_default_scope
                                                        end

      rescue_from_uniqueness_error do
        create_params[oauth_applications_client_id_column] = oauth_unique_id_generator
        db[oauth_applications_table].insert(create_params)
      end
    end
  end
end
