# frozen-string-literal: true

module Rodauth
  Feature.define(:oauth, :Oauth) do
    SCOPES = %w[profile.read]

    depends :login

    before "authorize"
    after "authorize"
    after "authorize_failure"

    before "token"
    after "token"

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

    auth_value_method :json_response_content_type, "application/json"

    auth_value_method :oauth_grant_expires_in, 60 * 5 # 5 minutes
    auth_value_method :oauth_token_expires_in, 60 * 60 # 60 minutes

    # URL PARAMS
    auth_value_method :grant_type_param, "grant_type"
    auth_value_method :authorize_code_param, "code"
    auth_value_method :client_id_param, "client_id"
    auth_value_method :scopes_param, "scope"
    auth_value_method :state_param, "state"
    auth_value_method :callback_url_param, "callback_url"
    auth_value_method :oauth_scopes_param, "scopes"

    # OAuth Token
    auth_value_method :oauth_tokens_table, :oauth_tokens
    auth_value_method :oauth_tokens_token_column, :token
    auth_value_method :oauth_tokens_refresh_token_column, :refresh_token
    auth_value_method :oauth_tokens_scopes_column, :scopes
    auth_value_method :oauth_tokens_oauth_application_id_column, :oauth_application_id
    auth_value_method :oauth_tokens_oauth_grant_id_column, :oauth_grant_id
    auth_value_method :oauth_grants_revoked_at_column, :revoked_at

    # OAuth Grants    
    auth_value_method :oauth_grants_table, :oauth_grants
    auth_value_method :oauth_grants_key, :id
    auth_value_method :oauth_grants_account_id_column, :account_id
    auth_value_method :oauth_grants_oauth_application_id_column, :oauth_application_id
    auth_value_method :oauth_grants_code_column, :code
    auth_value_method :oauth_grants_expires_in_column, :expires_in
    auth_value_method :oauth_grants_scopes_column, :scopes

    auth_value_method :token_column, :token
    auth_value_method :authorization_required_error_status, 403
    auth_value_method :invalid_oauth_response_status, 400


    # OAuth Applications
    auth_value_method :oauth_applications_path, "oauth-applications"
    auth_value_method :oauth_applications_table, :oauth_applications
    auth_value_method :oauth_application_name_column, :name
    auth_value_method :oauth_application_description_column, :description
    auth_value_method :oauth_application_scopes_column, :scopes
    auth_value_method :oauth_application_client_id_column, :client_id
    auth_value_method :oauth_application_client_secret_column, :client_secret
    auth_value_method :oauth_application_homepage_url_column, :homepage_url
    auth_value_method :oauth_application_callback_url_column, :callback_url
    auth_value_method :oauth_application_key, :id

    auth_value_method :oauth_application_default_scope, SCOPES.first
    auth_value_method :oauth_application_scopes, SCOPES

    auth_value_method :oauth_application_client_id_column, :client_id
    auth_value_method :oauth_application_callback_url_column, :callback_url
    auth_value_method :oauth_application_scopes_column, :scopes

    auth_value_method :oauth_application_name_key, "name"
    auth_value_method :oauth_application_description_key, "description"
    auth_value_method :oauth_application_scopes_key, "scopes"
    auth_value_method :oauth_application_client_id_key, "client_id"
    auth_value_method :oauth_application_client_secret_key, "client_secret"
    auth_value_method :oauth_application_homepage_url_key, "homepage_url"
    auth_value_method :oauth_application_callback_url_key, "callback_url"
    auth_value_method :oauth_application_id, Integer

    auth_value_method :invalid_grant_type_message, "Invalid grant type"
    auth_value_method :invalid_url_message, "Invalid URL"
    auth_value_method :invalid_grant_message, "Invalid grant"
    auth_value_method :unique_error_message, "is already in use"
    auth_value_method :null_error_message, "is not filled"

    auth_value_methods(
      :state,
      :oauth_application,
      :callback_url,
      :client_id,
      :scopes
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

    def scopes
      scopes = param(oauth_scopes_param)

      return oauth_application_default_scope unless scopes && !scopes.empty?
      scopes
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

        elsif key == oauth_application_scopes_key

          value.each do |scope|
            unless oauth_application_scopes.include?(scope)
              set_field_error(key, invalid_scope_message)
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
        oauth_application_scopes_column => oauth_application_params[oauth_application_scopes_key],
        oauth_application_homepage_url_column => oauth_application_params[oauth_application_homepage_url_key], 
        oauth_application_callback_url_column => oauth_application_params[oauth_application_callback_url_key],
      }

      # set client ID/secret pairs
      create_params.merge! \
        oauth_application_client_id_column => SecureRandom.uuid,
        oauth_application_client_secret_column => SecureRandom.uuid

      if create_params[oauth_application_scopes_column]
        create_params[oauth_application_scopes_column] = create_params[oauth_application_scopes_column].join(",")
      else
        create_params[oauth_application_scopes_column] = oauth_application_default_scope
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

    def oauth_authorize(scope = oauth_application_default_scope)
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

    end


    # Access Tokens

    def validate_oauth_token_params
      unless param(client_id_param)
        throw_json_response_error(invalid_oauth_response_status, "invalid_request")
      end

      unless (grant_type = param(grant_type_param))
        throw_json_response_error(invalid_oauth_response_status, "invalid_request")
      end

      case grant_type
      when "authorization_code"
        unless param(authorize_code_param)
          throw_json_response_error(invalid_oauth_response_status, "invalid_request")
        end

        # TODO: verify grant redirect_uri
      when "token"
        unless param(refresh_token_param)
          throw_json_response_error(invalid_oauth_response_status, "invalid_request")
        end
      else
        throw_json_response_error(invalid_oauth_response_status, "invalid_request")
      end
    end

    private

    def create_oauth_grant
      create_params = {
        oauth_grants_account_id_column => account_id,
        oauth_grants_oauth_application_id_column => oauth_application[oauth_application_key],
        oauth_grants_code_column => SecureRandom.uuid,
        oauth_grants_expires_in_column => Time.now + oauth_grant_expires_in,
        oauth_grants_scopes_column => scopes
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

    def create_oauth_token
      case param(grant_type_param)
      when "authorization_code"
        # fetch oauth grant
        oauth_grant = db[oauth_grants_table].where(
          oauth_grants_code_column => param(authorize_code_param),
          oauth_grants_oauth_application_id_column => db[oauth_applications_table].where(
              oauth_application_client_id_column => param(client_id_param)
            ).select(oauth_application_key),
        ).where(Sequel[oauth_grants_expires_in_column] >= Sequel::CURRENT_TIMESTAMP)
         .where(oauth_grants_revoked_at_column => nil)
         .first

        throw_json_response_error(invalid_oauth_response_status, "invalid_grant") unless oauth_grant

        create_params = {
          oauth_tokens_oauth_application_id_column => oauth_grant[oauth_grants_oauth_application_id_column],
          oauth_tokens_oauth_grant_id_column => oauth_grant[oauth_grants_key],
          oauth_tokens_scopes_column => oauth_grant[oauth_grants_scopes_column],
          oauth_grants_expires_in_column => Time.now + oauth_token_expires_in,
          oauth_tokens_refresh_token_column => SecureRandom.uuid,
          oauth_tokens_token_column => SecureRandom.uuid
        }

        # revoke oauth grant
        db[oauth_grants_table].where(oauth_grants_key => oauth_grant[oauth_grants_key])
                              .update(oauth_grants_revoked_at_column => Sequel::CURRENT_TIMESTAMP)

        ds = db[oauth_tokens_table]

        begin
          if ds.supports_returning?(:insert)
            ds.returning.insert(create_params)
          else
            id = ds.insert(create_params)
            ds.where(oauth_grants_key => id).first
          end
        rescue Sequel::UniqueConstraintViolation => e
         retry 
        end
      else
        throw_json_response_error(invalid_grant_status, "invalid_grant")
      end
    end

    def throw_json_response_error(status, error_code)
      response.status = status
      payload = { "error" => error_code }
      response['Content-Type'] ||= json_response_content_type
      response.write(request.send(:convert_to_json, payload))
      request.halt
    end

    def authorization_required
      set_redirect_error_status(authorization_required_error_status)
      set_redirect_error_flash(require_authorization_error_flash)
      redirect(require_authorization_redirect)
    end

    def oauth_grant_valid_parameters_required
      set_redirect_error_status(invalid_oauth_response_status)
      set_redirect_error_flash(oauth_grant_valid_parameters_error_flash)
      redirect(request.referer || default_redirect)
    end

    def require_oauth_application
      oauth_grant_valid_parameters_required unless oauth_application
    end

    def require_oauth_grant_valid_parameters
      oauth_grant_valid_parameters_required unless oauth_application && check_valid_scopes? && check_valid_callback_url?
    end

    def check_valid_scopes?
      return false unless scopes

      (scopes.split(",") - oauth_application[oauth_application_scopes_column].split(",")).empty?
    end

    def check_valid_callback_url?
      callback_url == oauth_application[oauth_application_callback_url_column]
    end
   
    route(:oauth_token) do |r|

      # access-token
      request.post do
        catch_error do
          validate_oauth_token_params

          oauth_token = nil
          transaction do
            before_token
            oauth_token = create_oauth_token
            after_token
          end

          response.status = 200
          response['Content-Type'] ||= json_response_content_type
          json_response = {
            "token" => oauth_token[:token],
            "refresh_token" => oauth_token[:refresh_token],
            "expires_in" => (oauth_token[:expires_in] - Time.now).to_i
          }
          response.write(request.__send__(:convert_to_json, json_response))
          request.halt
        end
        # TODO: JSON ERROR
        response.status = invalid_field_error_status
        response['Content-Type'] ||= json_response_content_type
      end
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
        unless check_valid_scopes?
          after_authorize_failure
          throw_error_status(authorize_error_status, scopes_param, invalid_scope_message)
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
          code = create_oauth_grant
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
