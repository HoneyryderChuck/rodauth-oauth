# frozen-string-literal: true

module Rodauth
  Feature.define(:oauth, :OAuth) do
    SCOPES = %w[profile.read].freeze

    depends :login

    before "authorize"
    after "authorize"
    after "authorize_failure"

    before "token"
    after "token"

    before "revoke"
    after "revoke"

    before "create_oauth_application"
    after "create_oauth_application"

    error_flash "OAuth Authorization invalid parameters", "oauth_grant_valid_parameters"

    error_flash "Please authorize to continue", "require_authorization"
    error_flash "There was an error registering your oauth application", "create_oauth_application"
    notice_flash "Your oauth application has been registered", "create_oauth_application"

    notice_flash "The oauth token has been revoked", "revoke_oauth_token"

    view "oauth_authorize", "Authorize", "authorize"
    view "oauth_applications", "Oauth Applications", "oauth_applications"
    view "oauth_application", "Oauth Application", "oauth_application"
    view "new_oauth_application", "New Oauth Application", "new_oauth_application"
    view "oauth_tokens", "Oauth Tokens", "oauth_tokens"

    auth_value_method :json_response_content_type, "application/json"

    auth_value_method :oauth_grant_expires_in, 60 * 5 # 5 minutes
    auth_value_method :oauth_token_expires_in, 60 * 60 # 60 minutes

    # URL PARAMS

    # Authorize / token
    %w[
      grant_type code refresh_token client_id scope
      state redirect_uri scopes token_type_hint token
      access_type
    ].each do |param|
      auth_value_method :"#{param}_param", param
    end

    # Application
    APPLICATION_REQUIRED_PARAMS = %w[name description scopes homepage_url redirect_uri].freeze
    auth_value_method :oauth_application_required_params, APPLICATION_REQUIRED_PARAMS

    (APPLICATION_REQUIRED_PARAMS + %w[client_id client_secret]).each do |param|
      auth_value_method :"oauth_application_#{param}_param", param
    end

    # OAuth Token
    auth_value_method :oauth_tokens_path, "oauth-tokens"
    auth_value_method :oauth_tokens_table, :oauth_tokens
    auth_value_method :oauth_tokens_id_column, :id

    %i[
      oauth_application_id oauth_token_id oauth_grant_id account_id
      token refresh_token scopes
      expires_in revoked_at
    ].each do |column|
      auth_value_method :"oauth_tokens_#{column}_column", column
    end

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

    auth_value_method :authorization_required_error_status, 401
    auth_value_method :invalid_oauth_response_status, 400

    # OAuth Applications
    auth_value_method :oauth_applications_path, "oauth-applications"
    auth_value_method :oauth_applications_table, :oauth_applications

    auth_value_method :oauth_applications_id_column, :id
    auth_value_method :oauth_applications_id_pattern, Integer

    %i[
      account_id
      name description scopes
      client_id client_secret
      homepage_url redirect_uri
    ].each do |column|
      auth_value_method :"oauth_applications_#{column}_column", column
    end

    auth_value_method :oauth_application_default_scope, SCOPES.first
    auth_value_method :oauth_application_scopes, SCOPES
    auth_value_method :oauth_token_type, "Bearer"

    auth_value_method :invalid_request, "Request is missing a required parameter"
    auth_value_method :invalid_client, "Invalid client"
    auth_value_method :unauthorized_client, "Unauthorized client"
    auth_value_method :invalid_grant_type_message, "Invalid grant type"
    auth_value_method :invalid_grant_message, "Invalid grant"
    auth_value_method :invalid_scope_message, "Invalid scope"

    auth_value_method :invalid_url_message, "Invalid URL"
    auth_value_method :unsupported_token_type_message, "Invalid token type hint"

    auth_value_method :unique_error_message, "is already in use"
    auth_value_method :null_error_message, "is not filled"

    auth_value_methods(
      :oauth_unique_id_generator
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

    auth_value_method :json_request_accept_regexp, %r{\bapplication/(?:vnd\.api\+)?json\b}i
    auth_methods(:json_request?)

    def check_csrf?
      case request.path
      when oauth_token_path
        false
      when oauth_revoke_path
        !json_request?
      else
        super
      end
    end

    # Overrides logged_in?, so that a valid authorization token also authnenticates a request
    def logged_in?
      super || authorization_token
    end

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

      return [oauth_application_default_scope] unless scopes && !scopes.empty?

      scopes.split(" ")
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

    def token_type_hint
      token_type_hint = param(token_type_hint_param)

      return "access_token" unless token_type_hint && !token_type_hint.empty?

      token_type_hint
    end

    def token
      token = param(token_param)

      return unless token && !token.empty?

      token
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
      return @authorization_token if defined?(@authorization_token)

      @authorization_token = begin
        value = request.get_header("HTTP_AUTHORIZATION").to_s

        scheme, token = value.split(" ", 2)

        return unless scheme == "Bearer"

        # check if there is a token
        # check if token has not expired
        # check if token has been revoked
        db[oauth_tokens_table].where(oauth_tokens_token_column => token)
                              .where(Sequel[oauth_tokens_expires_in_column] >= Sequel::CURRENT_TIMESTAMP)
                              .where(oauth_tokens_revoked_at_column => nil)
                              .first
      end
    end

    def require_oauth_authorization(*scopes)
      authorization_required unless authorization_token

      scopes << oauth_application_default_scope if scopes.empty?

      token_scopes = authorization_token[:scopes].split(",")

      authorization_required unless scopes.any? { |scope| token_scopes.include?(scope) }
    end

    # /oauth-applications routes
    def oauth_applications
      request.on(oauth_applications_path) do
        require_account

        request.get "new" do
          new_oauth_application_view
        end
        request.on(oauth_applications_id_pattern) do |id|
          oauth_application = db[oauth_applications_table].where(oauth_applications_id_column => id).first
          scope.instance_variable_set(:@oauth_application, oauth_application)

          request.is do
            request.get do
              oauth_application_view
            end
          end

          request.on(oauth_tokens_path) do
            oauth_tokens = db[oauth_tokens_table].where(oauth_tokens_oauth_application_id_column => id)
            scope.instance_variable_set(:@oauth_tokens, oauth_tokens)
            oauth_tokens_view
          end
        end

        request.get do
          scope.instance_variable_set(:@oauth_applications, db[:oauth_applications])
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

    def oauth_unique_id_generator
      SecureRandom.uuid
    end

    # Oauth Application

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
        if key == oauth_application_homepage_url_param ||
           key == oauth_application_redirect_uri_param

          set_field_error(key, invalid_url_message) unless URI::DEFAULT_PARSER.make_regexp(%w[http https]).match?(value)

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
        oauth_applications_homepage_url_column => oauth_application_params[oauth_application_homepage_url_param],
        oauth_applications_redirect_uri_column => oauth_application_params[oauth_application_redirect_uri_param]
      }

      # set client ID/secret pairs
      create_params.merge! \
        oauth_applications_client_id_column => oauth_unique_id_generator,
        oauth_applications_client_secret_column => oauth_unique_id_generator

      create_params[oauth_applications_scopes_column] = if create_params[oauth_applications_scopes_column]
                                                          create_params[oauth_applications_scopes_column].join(",")
                                                        else
                                                          oauth_application_default_scope
                                                        end

      ds = db[oauth_applications_table]

      id = nil
      raised = begin
        id = if ds.supports_returning?(:insert)
               ds.returning(oauth_applications_id_column).insert(create_params)
             else
               id = db[oauth_applications_table].insert(create_params)
               db[oauth_applications_table].where(oauth_applications_id_column => id).get(oauth_applications_id_column)
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
        end
      end

      !raised && id
    end

    # Authorize

    def validate_oauth_grant_params
      unless oauth_application && check_valid_redirect_uri? && check_valid_access_type?
        redirect_response_error("invalid_request")
      end
      redirect_response_error("invalid_scope") unless check_valid_scopes?
    end

    def create_oauth_grant
      create_params = {
        oauth_grants_account_id_column => account_id,
        oauth_grants_oauth_application_id_column => oauth_application[oauth_applications_id_column],
        oauth_grants_redirect_uri_column => redirect_uri,
        oauth_grants_code_column => oauth_unique_id_generator,
        oauth_grants_expires_in_column => Time.now + oauth_grant_expires_in,
        oauth_grants_scopes_column => scopes.join(",")
      }

      unless (access_type = param("access_type")).empty?
        create_params[oauth_grants_access_type_column] = access_type
      end

      ds = db[oauth_grants_table]

      begin
        if ds.supports_returning?(:insert)
          ds.returning(authorize_code_column).insert(create_params)
        else
          id = ds.insert(create_params)
          ds.where(oauth_grants_id_column => id).get(oauth_grants_code_column)
        end
      rescue Sequel::UniqueConstraintViolation
        retry
      end
    end

    # Access Tokens

    def validate_oauth_token_params
      redirect_response_error("invalid_request") unless param(client_id_param)

      unless (grant_type = param(grant_type_param))
        redirect_response_error("invalid_request")
      end

      case grant_type
      when "authorization_code"
        redirect_response_error("invalid_request") unless param(code_param)

      when "refresh_token"
        redirect_response_error("invalid_request") unless param(refresh_token_param)
      else
        redirect_response_error("invalid_request")
      end
    end

    def create_oauth_token
      case param(grant_type_param)
      when "authorization_code"
        # fetch oauth grant
        oauth_grant = db[oauth_grants_table].where(
          oauth_grants_code_column => param(code_param),
          oauth_grants_redirect_uri_column => param(redirect_uri_param),
          oauth_grants_oauth_application_id_column => db[oauth_applications_table].where(
            oauth_applications_client_id_column => param(client_id_param),
            oauth_applications_account_id_column => oauth_applications_account_id_column
          ).select(oauth_applications_id_column)
        ).where(Sequel[oauth_grants_expires_in_column] >= Sequel::CURRENT_TIMESTAMP)
                                            .where(oauth_grants_revoked_at_column => nil)
                                            .first

        redirect_response_error("invalid_grant") unless oauth_grant

        create_params = {
          oauth_tokens_account_id_column => oauth_grant[oauth_grants_account_id_column],
          oauth_tokens_oauth_application_id_column => oauth_grant[oauth_grants_oauth_application_id_column],
          oauth_tokens_oauth_grant_id_column => oauth_grant[oauth_grants_id_column],
          oauth_tokens_scopes_column => oauth_grant[oauth_grants_scopes_column],
          oauth_grants_expires_in_column => Time.now + oauth_token_expires_in,
          oauth_tokens_token_column => oauth_unique_id_generator
        }

        if oauth_grant[oauth_grants_access_type_column] == "offline"
          create_params[oauth_tokens_refresh_token_column] = oauth_unique_id_generator
        end
        # revoke oauth grant
        db[oauth_grants_table].where(oauth_grants_id_column => oauth_grant[oauth_grants_id_column])
                              .update(oauth_grants_revoked_at_column => Sequel::CURRENT_TIMESTAMP)

        ds = db[oauth_tokens_table]

        begin
          if ds.supports_returning?(:insert)
            ds.returning.insert(create_params)
          else
            id = ds.insert(create_params)
            ds.where(oauth_tokens_id_column => id).first
          end
        rescue Sequel::UniqueConstraintViolation
          retry
        end
      when "refresh_token"
        # fetch oauth grant
        oauth_token = db[oauth_tokens_table].where(
          oauth_tokens_refresh_token_column => param(refresh_token_param),
          oauth_tokens_oauth_application_id_column => db[oauth_applications_table].where(
            oauth_applications_client_id_column => param(client_id_param),
            oauth_applications_account_id_column => account_id
          ).select(oauth_applications_id_column)
        ).where(oauth_grants_revoked_at_column => nil)
                                            .first

        redirect_response_error("invalid_grant") unless oauth_token

        update_params = {
          oauth_tokens_oauth_application_id_column => oauth_token[oauth_grants_oauth_application_id_column],
          oauth_tokens_expires_in_column => Time.now + oauth_token_expires_in,
          oauth_tokens_token_column => oauth_unique_id_generator
        }

        ds = db[oauth_tokens_table].where(oauth_tokens_id_column => oauth_token[oauth_tokens_id_column])
        begin
          if ds.supports_returning?(:update)
            ds.returning.update(update_params)
          else
            ds.update(update_params)
            ds.first
          end
        rescue Sequel::UniqueConstraintViolation
          retry
        end
      else
        redirect_response_error("invalid_grant")
      end
    end

    # Token revocation

    TOKEN_HINT_TYPES = %w[access_token refresh_token].freeze

    def validate_oauth_revoke_params
      # check if valid token hint type
      redirect_response_error("unsupported_token_type") unless TOKEN_HINT_TYPES.include?(token_type_hint)

      redirect_response_error("invalid_request") unless param(token_param)
    end

    def revoke_oauth_token
      # one can only revoke tokens which haven't been revoked before, and which are
      # either our tokens, or tokens from applications we own.
      ds = db[oauth_tokens_table]
           .where(oauth_tokens_revoked_at_column => nil)
           .where(
             Sequel.or(
               oauth_tokens_account_id_column => account_id,
               oauth_tokens_oauth_application_id_column => db[oauth_applications_table].where(
                 oauth_applications_client_id_column => param(client_id_param),
                 oauth_applications_account_id_column => account_id
               ).select(oauth_applications_id_column)
             )
           )
      ds = case token_type_hint
           when "access_token"
             ds.where(oauth_tokens_token_column => token)
           when "refresh_token"
             ds.where(oauth_tokens_refresh_token_column => token)
           end

      oauth_token = ds.first
      redirect_response_error("invalid_request") unless oauth_token

      update_params = { oauth_tokens_revoked_at_column => Sequel::CURRENT_TIMESTAMP }

      ds = db[oauth_tokens_table].where(oauth_tokens_id_column => oauth_token[oauth_tokens_id_column])

      if ds.supports_returning?(:update)
        ds.returning.update(update_params)
      else
        ds.update(update_params)
        ds.first
      end

      # If the particular
      # token is a refresh token and the authorization server supports the
      # revocation of access tokens, then the authorization server SHOULD
      # also invalidate all access tokens based on the same authorization
      # grant
      #
      # we don't need to do anything here, as we revalidate existing tokens
    end

    # Response helpers

    def redirect_response_error(error_code)
      if json_request?
        throw_json_response_error(invalid_oauth_response_status, error_code)
      else
        redirect_url = URI.parse(request.referer || default_redirect)
        query_params = ["error=#{error_code}"]
        if respond_to?(:"#{error_code}_message")
          message = send(:"#{error_code}_message")
          query_params << ["error_description=#{CGI.escape(message)}"]
        end
        query_params << redirect_url.query if redirect_url.query
        redirect_url.query = query_params.join("&")
        redirect(redirect_url.to_s)
      end
    end

    def throw_json_response_error(status, error_code)
      response.status = status
      payload = { "error" => error_code }
      payload["error_description"] = send(:"#{error_code}_message") if respond_to?(:"#{error_code}_message")
      response["Content-Type"] ||= json_response_content_type
      response["WWW-Authenticate"] = "Bearer" if status == 401
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

      (scopes - oauth_application[oauth_applications_scopes_column].split(",")).empty?
    end

    def check_valid_redirect_uri?
      redirect_uri == oauth_application[oauth_applications_redirect_uri_column]
    end

    ACCESS_TYPES = %w[offline online].freeze

    def check_valid_access_type?
      access_type = param("access_type")
      access_type.empty? || ACCESS_TYPES.include?(access_type)
    end

    # /oauth-token
    route(:oauth_token) do |r|
      throw_json_response_error(authorization_required_error_status, "invalid_client") unless logged_in?

      # access-token
      r.post do
        catch_error do
          validate_oauth_token_params

          oauth_token = nil
          transaction do
            before_token
            oauth_token = create_oauth_token
            after_token
          end

          response.status = 200
          response["Content-Type"] ||= json_response_content_type
          json_response = {
            "token" => oauth_token[:token],
            "token_type" => oauth_token_type,
            "expires_in" => oauth_token_expires_in
          }

          json_response["refresh_token"] = oauth_token[:refresh_token] if oauth_token[:refresh_token]

          response.write(request.__send__(:convert_to_json, json_response))
          request.halt
        end

        throw_json_response_error(invalid_oauth_response_status, "invalid_request")
      end
    end

    # /oauth-revoke
    route(:oauth_revoke) do |r|
      require_account

      # access-token
      r.post do
        catch_error do
          validate_oauth_revoke_params

          oauth_token = nil
          transaction do
            before_revoke
            oauth_token = revoke_oauth_token
            after_revoke
          end

          if json_request?
            response.status = 200
            response["Content-Type"] ||= json_response_content_type
            json_response = {
              "token" => oauth_token[:token],
              "refresh_token" => oauth_token[:refresh_token],
              "revoked_at" => oauth_token[:revoked_at]
            }
            response.write(request.__send__(:convert_to_json, json_response))
            request.halt
          else
            set_notice_flash revoke_oauth_token_notice_flash
            redirect request.referer || "/"
          end
        end

        throw_json_response_error(invalid_oauth_response_status, "invalid_request")
      end
    end

    # /oauth-authorize
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
