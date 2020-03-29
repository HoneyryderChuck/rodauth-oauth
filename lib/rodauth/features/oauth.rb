# frozen-string-literal: true

module Rodauth
  Feature.define(:oauth, :Oauth) do
    GRANTS = %w[profile.read]

    depends :login

    before "create_oauth_application"
    after "create_oauth_application"

    error_flash "Please authorize to continue", "require_authorization"
    notice_flash "Your oauth application has been registered", "create_oauth_application"
    error_flash "There was an error registering your oauth application", "create_oauth_application"

    view "authorize", "Authorize", "authorize"
    view "oauth_applications", "Oauth Applications", "oauth_applications"
    view "oauth_application", "Oauth Application", "oauth_application"
    view "new_oauth_application", "New Oauth Application", "new_oauth_application"

    auth_value_method :grants_table, :oauth_grants
    auth_value_method :token_column, :token
    auth_value_method :authorization_required_error_status, 403

    auth_value_method :oauth_applications_path, "oauth-applications"
    auth_value_method :oauth_applications_table, :oauth_applications
    auth_value_method :oauth_application_default_grant, GRANTS.first
    auth_value_method :oauth_application_grants, GRANTS
    auth_value_method :oauth_application_key, :id
    auth_value_method :oauth_application_grants_key, "grants"
    auth_value_method :oauth_application_client_id_key, "client_id"
    auth_value_method :oauth_application_client_secret_key, "client_secret"
    auth_value_method :oauth_application_homepage_url_key, "homepage_url"
    auth_value_method :oauth_application_callback_url_key, "callback_url"
    auth_value_method :oauth_application_id, Integer

    auth_value_method :invalid_url_message, "Invalid URL"
    auth_value_method :invalid_grant_message, "Invalid grant"
    auth_value_method :unique_error_message, "is already in use"
    auth_value_method :null_error_message, "is not filled"

    session_key :flash_error_key, :error
    session_key :session_key, :account_id

    redirect(:oauth_application) do |id|
      "/#{oauth_applications_path}/#{id}"
    end

    redirect(:require_authorization) do
      if logged_in?
        authorize_path
      else
        login_redirect
      end
    end

    attr_reader :oauth_application

    def initialize(scope)
      @scope = scope
    end

   
    def grant
      param(oauth_grant_param) || oauth_application_default_grant
    end

    def authorization_token
      value = request["HTTP_AUTHORIZATION"].to_s

      scheme, token = value.split(" ", 2)

      authorization_required unless scheme == "Bearer"

      token
    end

    # Oauth Application

    def oauth_application_params
      @oauth_application_params ||= begin
        columns = db[oauth_applications_table].columns
        params = request.params.select { |k, value| columns.include?(k.to_sym) && !(value.nil? || value.empty?) }
        params
      end
    end

    def validate_oauth_application_params
      oauth_application_params.each do |key, value|
        if key == oauth_application_homepage_url_key ||
           key == oauth_application_callback_url_key

          unless URI.regexp(%w[http https]).match?(value)
            set_field_error(key, invalid_url_message)
          end

        elsif key == oauth_application_grants_key

          value.each do |grant|
            unless oauth_application_grants.include?(grant)
              set_field_error(key, invalid_grant_message)
            end
          end
        end
      end

      throw :rodauth_error if @field_errors && !@field_errors.empty?
    end

    def create_oauth_application
      create_params = oauth_application_params

      # set client ID/secret pairs
      create_params.merge! \
        oauth_application_client_id_key => SecureRandom.uuid,
        oauth_application_client_secret_key => SecureRandom.uuid

      if create_params[oauth_application_grants_key]
        create_params[oauth_application_grants_key] = create_params[oauth_application_grants_key].join(",")
      else
        create_params[oauth_application_grants_key] = oauth_application_default_grant
      end

      ds = db[oauth_applications_table]

      id = nil
      raised = begin
        id = if ds.supports_returning?(:insert)
          ds.returning(oauth_application_key).insert(create_params)
        else
          id = db[oauth_applications_table].insert(create_params)
          db[oauth_applications_table].where(id: id).get(oauth_application_key)
        end
        false
      rescue Sequel::ConstraintViolation => e
        e
      end

      if raised
        field = raised.message[/\.(.*)$/, 1]
        case raised
        when Sequel::UniqueConstraintViolation
          throw_error(field, unique_error_message)
        when Sequel::NotNullConstraintViolation
          throw_error(field, null_error_message)
        else
        end
      end

      !raised && id
    end


    # /oauth-applications routes
    def oauth_applications
      request.on(oauth_applications_path) do
        request.get "new" do
          new_oauth_application_view
        end
        request.on(oauth_application_id) do |id|
          request.get do
            @oauth_application = db[oauth_applications_table].where(oauth_application_key => id).first
            oauth_application_view
          end
        end
        request.get do
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
              redirect oauth_application_redirect(id)
            end
          end
          set_error_flash create_oauth_application_error_flash
          new_oauth_application_view
        end
      end
    end

    # Authorize

    def oauth_authorize(scope = oauth_application_default_grant)
      grant = db[grants_table].filter(token_column => authorization_token).first

      # check if there is grant
      # check if grant was expired
      # check if grant has been revoked
      # check if permission for scoep exists
      if !grant ||
         Time.now.utc > (grant[:created_at] + expires_in.seconds) ||
         (grant[:revoked_at] && Time.now.utc > grant[:revoked_at]) ||
         !grants[:scopes].include?(scope)
        authorization_required
      end

      # Client applications
    end

    def authorization_required
      set_redirect_error_status(authorization_required_error_status)
      set_redirect_error_flash(require_authorization_error_flash)
      redirect(require_authorization_redirect)
    end

   
    route(:oauth_authorize) do |r|
      require_account

      r.get do
        authorize_view
      end
    end
  end
end
