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

    # Authorize / token
    %w[grant_type code client_id scope state redirect_uri scopes].each do |param|
      auth_value_method :"#{param}_param", param
    end


    # Application
    %w[name description scopes client_id client_secret homepage_url redirect_uri].each do |param|
      auth_value_method :"oauth_application_#{param}_key", param
    end

    # OAuth Token
    auth_value_method :oauth_tokens_table, :oauth_tokens

    %i[
      oauth_application_id oauth_token_id oauth_grant_id
      token refresh_token scopes
      expires_in revoked_at
    ].each do |column|
      auth_value_method :"oauth_tokens_#{column}_column", column
    end

    # OAuth Grants    
    auth_value_method :oauth_grants_table, :oauth_grants
    auth_value_method :oauth_grants_key, :id
    %i[
      account_id oauth_application_id
      code scopes
      expires_in revoked_at
    ].each do |column|
      auth_value_method :"oauth_grants_#{column}_column", column
    end

    auth_value_method :authorization_required_error_status, 401
    auth_value_method :invalid_oauth_response_status, 400


    # OAuth Applications
    auth_value_method :oauth_applications_path, "oauth-applications"
    auth_value_method :oauth_applications_table, :oauth_applications

    auth_value_method :oauth_applications_key, :id
    auth_value_method :oauth_applications_id_pattern, Integer

    %i[
      name description scopes
      client_id client_secret
      homepage_url redirect_uri
    ].each do |column|
      auth_value_method :"oauth_applications_#{column}_column", column
    end

    auth_value_method :oauth_application_default_scope, SCOPES.first
    auth_value_method :oauth_application_scopes, SCOPES

    auth_value_method :invalid_request, "Request is missing a required parameter"
    auth_value_method :invalid_client, "Invalid client"
    auth_value_method :unauthorized_client, "Unauthorized client"
    auth_value_method :invalid_grant_type_message, "Invalid grant type"
    auth_value_method :invalid_grant_message, "Invalid grant"
    auth_value_method :invalid_scope_message, "Invalid scope"

    auth_value_method :invalid_url_message, "Invalid URL"

    auth_value_method :unique_error_message, "is already in use"
    auth_value_method :null_error_message, "is not filled"

    auth_value_methods(
      :state,
      :oauth_application,
      :redirect_uri,
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

    auth_value_method :json_request_accept_regexp, /\bapplication\/(?:vnd\.api\+)?json\b/i
    auth_methods(:json_request?)

    def json_request?
      return @json_request if defined?(@json_request)
      @json_request = request.get_header("HTTP_ACCEPT") =~ json_request_accept_regexp
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
      scopes = param(scopes_param)

      return oauth_application_default_scope unless scopes && !scopes.empty?
      scopes
    end

    def client_id
      client_id = param(client_id_param)

      return unless client_id && !client_id.empty?
      client_id
    end

    def redirect_uri
      redirect_uri = param(redirect_uri_param)

      return oauth_application[oauth_applications_redirect_uri_column] unless redirect_uri && !redirect_uri.empty?
      redirect_uri
    end


    def oauth_application
      return @oauth_application if defined?(@oauth_application)

      @oauth_application = begin
        client_id = param(client_id_param)

        return unless client_id

        db[oauth_applications_table].filter(oauth_applications_client_id_column => client_id).first
      end
    end

    def authorization_token
      value = request.get_header("HTTP_AUTHORIZATION").to_s

      scheme, token = value.split(" ", 2)

      authorization_required unless scheme == "Bearer"

      token
    end

    def oauth_authorize(scopes = oauth_application_default_scope)
      # check if there is a token 
      oauth_token = db[oauth_tokens_table].where(oauth_tokens_token_column => authorization_token)
        # check if token has not expired 
        .where(Sequel[oauth_tokens_expires_in_column] >= Sequel::CURRENT_TIMESTAMP)
        # check if token has been revoked
        .where(oauth_tokens_revoked_at_column => nil)
        .first

      authorization_required unless oauth_token

      # check token scopes
      scopes = scopes.split(",") if scopes.respond_to?(:split)

      token_scopes = oauth_token[:scopes].split(",")

      authorization_required unless scopes.any? { |scope| token_scopes.include?(scope) }
    end

    

    # /oauth-applications routes
    def oauth_applications
      request.on(oauth_applications_path) do
        request.get "new" do
          new_oauth_application_view
        end
        request.on(oauth_applications_id_pattern) do |id|
          request.get do
            @oauth_application = db[oauth_applications_table].where(oauth_applications_key => id).first
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

    private

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
           key == oauth_application_redirect_uri_key

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
        oauth_applications_name_column => oauth_application_params[oauth_application_name_key],
        oauth_applications_description_column => oauth_application_params[oauth_application_description_key],
        oauth_applications_scopes_column => oauth_application_params[oauth_application_scopes_key],
        oauth_applications_homepage_url_column => oauth_application_params[oauth_application_homepage_url_key], 
        oauth_applications_redirect_uri_column => oauth_application_params[oauth_application_redirect_uri_key],
      }

      # set client ID/secret pairs
      create_params.merge! \
        oauth_applications_client_id_column => SecureRandom.uuid,
        oauth_applications_client_secret_column => SecureRandom.uuid

      if create_params[oauth_applications_scopes_column]
        create_params[oauth_applications_scopes_column] = create_params[oauth_applications_scopes_column].join(",")
      else
        create_params[oauth_applications_scopes_column] = oauth_application_default_scope
      end

      ds = db[oauth_applications_table]

      id = nil
      raised = begin
        id = if ds.supports_returning?(:insert)
          ds.returning(oauth_applications_key).insert(create_params)
        else
          id = db[oauth_applications_table].insert(create_params)
          db[oauth_applications_table].where(oauth_applications_key => id).get(oauth_applications_key)
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

    # Authorize


    def validate_oauth_grant_params
      redirect_response_error("invalid_request") unless oauth_application && check_valid_redirect_uri?
      redirect_response_error("invalid_scope") unless check_valid_scopes?
    end

    def create_oauth_grant
      create_params = {
        oauth_grants_account_id_column => account_id,
        oauth_grants_oauth_application_id_column => oauth_application[oauth_applications_key],
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
        unless param(code_param)
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


    def create_oauth_token
      case param(grant_type_param)
      when "authorization_code"
        # fetch oauth grant
        oauth_grant = db[oauth_grants_table].where(
          oauth_grants_code_column => param(code_param),
          oauth_grants_oauth_application_id_column => db[oauth_applications_table].where(
              oauth_applications_client_id_column => param(client_id_param)
            ).select(oauth_applications_key),
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

    def redirect_response_error(error_code)
      redirect_url = URI.parse(request.referer || default_redirect)
      query_params = ["error=#{error_code}"]
      query_params << redirect_url.query if redirect_url.query
      redirect_url.query = query_params.join("&")
      redirect(redirect_url.to_s)
    end

    def throw_json_response_error(status, error_code)
      response.status = status
      payload = { "error" => error_code }
      response['Content-Type'] ||= json_response_content_type
      response['WWW-Authenticate'] = "Bearer" if status == 401
      response.write(request.send(:convert_to_json, payload))
      request.halt
    end

    def authorization_required
      if json_request?
        throw_json_response_error(authorization_required_error_status, "invalid_client")
      else
        set_redirect_error_flash(require_authorization_error_flash)
        redirect(require_authorization_redirect)
      end
    end


    def check_valid_scopes?
      return false unless scopes

      (scopes.split(",") - oauth_application[oauth_applications_scopes_column].split(",")).empty?
    end

    def check_valid_redirect_uri?
      redirect_uri == oauth_application[oauth_applications_redirect_uri_column]
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
        validate_oauth_grant_params
        authorize_view
      end

      r.post do
        validate_oauth_grant_params

        code = nil
        transaction do
          before_authorize
          code = create_oauth_grant
          after_authorize
        end

        redirect_url = URI.parse(redirect_uri)
        query_params = ["code=#{code}"]
        query_params << "state=#{state}" if state
        query_params << redirect_url.query if redirect_url.query
        redirect_url.query = query_params.join("&")

        redirect(redirect_url.to_s)
      end
    end
  end
end
