# frozen-string-literal: true

module Rodauth
  Feature.define(:oauth, :Oauth) do
    GRANTS = %w[profile.read]

    depends :login

    before "authorize"
    after "authorize"
    after "authorize_failure"

    before "create_oauth_application"
    after "create_oauth_application"

    error_flash "OAuth Authorization invalid parameters", "oauth_grant_valid_parameters"

    error_flash "Please authorize to continue", "require_authorization"
    error_flash "There was an error registering your oauth application", "create_oauth_application"
    notice_flash "Your oauth application has been registered", "create_oauth_application"

    view "authorize", "Authorize", "authorize"
    view "oauth_applications", "Oauth Applications", "oauth_applications"
    view "oauth_application", "Oauth Application", "oauth_application"
    view "new_oauth_application", "New Oauth Application", "new_oauth_application"

    auth_value_method :oauth_grant_expires_in, 60 * 5 # 5 minuts

    # URL PARAMS
    auth_value_method :client_id_param, "client_id"
    auth_value_method :grants_param, "scope"
    auth_value_method :state_param, "state"
    auth_value_method :callback_url_param, "callback_url"
    auth_value_method :oauth_grants_param, "scopes"

    # OAuth Token
    auth_value_method :oauth_tokens_table, :oauth_tokens
    auth_value_method :oauth_tokens_token_column, :token

    # OAuth Grants    
    auth_value_method :oauth_grants_table, :oauth_grants
    auth_value_method :oauth_grants_key, :id
    auth_value_method :oauth_grants_account_id_column, :account_id
    auth_value_method :oauth_grants_oauth_application_id_column, :oauth_application_id
    auth_value_method :oauth_grants_code_column, :code
    auth_value_method :oauth_grants_expires_in_column, :expires_in
    auth_value_method :oauth_grants_grants_column, :grants

    auth_value_method :token_column, :token
    auth_value_method :authorization_required_error_status, 403
    auth_value_method :oauth_grant_valid_parameters_required_error_status, 422


    # OAuth Applications
    auth_value_method :oauth_applications_path, "oauth-applications"
    auth_value_method :oauth_applications_table, :oauth_applications
    auth_value_method :oauth_application_name_column, :name
    auth_value_method :oauth_application_description_column, :description
    auth_value_method :oauth_application_grants_column, :grants
    auth_value_method :oauth_application_client_id_column, :client_id
    auth_value_method :oauth_application_client_secret_column, :client_secret
    auth_value_method :oauth_application_homepage_url_column, :homepage_url
    auth_value_method :oauth_application_callback_url_column, :callback_url
    auth_value_method :oauth_application_key, :id

    auth_value_method :oauth_application_default_grant, GRANTS.first
    auth_value_method :oauth_application_grants, GRANTS

    auth_value_method :oauth_application_client_id_column, :client_id
    auth_value_method :oauth_application_callback_url_column, :callback_url
    auth_value_method :oauth_application_grants_column, :grants

    auth_value_method :oauth_application_name_key, "name"
    auth_value_method :oauth_application_description_key, "description"
    auth_value_method :oauth_application_grants_key, "scopes"
    auth_value_method :oauth_application_client_id_key, "client_id"
    auth_value_method :oauth_application_client_secret_key, "client_secret"
    auth_value_method :oauth_application_homepage_url_key, "homepage_url"
    auth_value_method :oauth_application_callback_url_key, "callback_url"
    auth_value_method :oauth_application_id, Integer

    auth_value_method :invalid_url_message, "Invalid URL"
    auth_value_method :invalid_grant_message, "Invalid grant"
    auth_value_method :unique_error_message, "is already in use"
    auth_value_method :null_error_message, "is not filled"

    auth_value_methods(
      :state,
      :oauth_application,
      :callback_url,
      :client_id,
      :grants
    )

    redirect(:oauth_application) do |id|
      "/#{oauth_applications_path}/#{id}"
    end

    redirect(:require_authorization) do
      if logged_in?
        oauth_authorize_path
      else
        login_redirect
      end
    end

    attr_reader :oauth_application

    def initialize(scope)
      @scope = scope
    end

    def state
      state = param(state_param)

      return unless state && !state.empty?
      state
    end

    def grants
      grants = param(oauth_grants_param)

      return oauth_application_default_grant unless grants && !grants.empty?
      grants
    end

    def client_id
      client_id = param(client_id_param)

      return unless client_id && !client_id.empty?
      client_id
    end

    def callback_url
      callback_url = param(callback_url_param)

      return oauth_application[oauth_application_callback_url_column] unless callback_url && !callback_url.empty?
      callback_url
    end


    def oauth_application
      return @oauth_application if defined?(@oauth_application)

      @oauth_application = begin
        client_id = param(client_id_param)

        return unless client_id

        db[oauth_applications_table].filter(oauth_application_client_id_column => client_id).first
      end
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
      create_params = {
        oauth_application_name_column => oauth_application_params[oauth_application_name_key],
        oauth_application_description_column => oauth_application_params[oauth_application_description_key],
        oauth_application_grants_column => oauth_application_params[oauth_application_grants_key],
        oauth_application_homepage_url_column => oauth_application_params[oauth_application_homepage_url_key], 
        oauth_application_callback_url_column => oauth_application_params[oauth_application_callback_url_key],
      }

      # set client ID/secret pairs
      create_params.merge! \
        oauth_application_client_id_column => SecureRandom.uuid,
        oauth_application_client_secret_column => SecureRandom.uuid

      if create_params[oauth_application_grants_column]
        create_params[oauth_application_grants_column] = create_params[oauth_application_grants_column].join(",")
      else
        create_params[oauth_application_grants_column] = oauth_application_default_grant
      end

      ds = db[oauth_applications_table]

      id = nil
      raised = begin
        id = if ds.supports_returning?(:insert)
          ds.returning(oauth_application_key).insert(create_params)
        else
          id = db[oauth_applications_table].insert(create_params)
          db[oauth_applications_table].where(oauth_application_key => id).get(oauth_application_key)
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
      grant = db[oauth_tokens_table].filter(oauth_tokens_token_column => authorization_token).first

      # check if there is grant
      # check if grant was expires_ind
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

    private

    def create_access_grant
      create_params = {
        oauth_grants_account_id_column => account_id,
        oauth_grants_oauth_application_id_column => oauth_application[oauth_application_key],
        oauth_grants_code_column => SecureRandom.uuid,
        oauth_grants_expires_in_column => Time.now + oauth_grant_expires_in,
        oauth_grants_grants_column => grants
      }

      ds = db[oauth_grants_table]

      begin
        if ds.supports_returning?(:insert)
          ds.returning(authorize_code_column).insert(create_params)
        else
          id = ds.insert(create_params)
          ds.where(oauth_grants_key => id).get(oauth_grants_code_column)
        end
      rescue Sequel::UniqueConstraintViolation => e
       retry 
      end
    end

    def authorization_required
      set_redirect_error_status(authorization_required_error_status)
      set_redirect_error_flash(require_authorization_error_flash)
      redirect(require_authorization_redirect)
    end

    def oauth_grant_valid_parameters_required
      set_redirect_error_status(oauth_grant_valid_parameters_required_error_status)
      set_redirect_error_flash(oauth_grant_valid_parameters_error_flash)
      redirect(request.referer || default_redirect)
    end

    def require_oauth_application
      oauth_grant_valid_parameters_required unless oauth_application
    end

    def require_oauth_grant_valid_parameters
      oauth_grant_valid_parameters_required unless oauth_application && check_valid_grant? && check_valid_callback_url?
    end

    def check_valid_grant?
      return false unless grants

      (grants.split(",") - oauth_application[oauth_application_grants_column].split(",")).empty?
    end

    def check_valid_callback_url?
      callback_url == oauth_application[oauth_application_callback_url_column]
    end
   
    route(:oauth_authorize) do |r|
      require_account

      r.get do
        require_oauth_grant_valid_parameters
        authorize_view
      end

      r.post do
        require_oauth_application

        # check if grants are valid for the application
        unless check_valid_grant?
          after_authorize_failure
          throw_error_status(authorize_error_status, grants_param, invalid_grant_message)
        end

        # check if there was a callback url, and verify it
        # TODO: check again what to do here compliance-wise
        unless check_valid_callback_url?
          after_authorize_failure
          throw_error_status(authorize_error_status, callback_url_param, invalid_callback_url_message)
        end

        code = nil
        transaction do
          before_authorize
          code = create_access_grant
          after_authorize
        end

        redirect_url = URI.parse(callback_url)
        query_params = ["code=#{code}"]
        query_params << "state=#{state}" if state
        query_params << redirect_url.query if redirect_url.query
        redirect_url.query = query_params.join("&")

        redirect(redirect_url.to_s)
      end
    end
  end
end
