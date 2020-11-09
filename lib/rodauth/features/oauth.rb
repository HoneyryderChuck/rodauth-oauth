# frozen-string-literal: true

require "time"
require "base64"
require "securerandom"
require "net/http"

require "rodauth/oauth/ttl_store"
require "rodauth/oauth/database_extensions"

module Rodauth
  Feature.define(:oauth) do
    # RUBY EXTENSIONS
    unless Regexp.method_defined?(:match?)
      # If you wonder why this is there: the oauth feature uses a refinement to enhance the
      # Regexp class locally with #match? , but this is never tested, because ActiveSupport
      # monkey-patches the same method... Please ActiveSupport, stop being so intrusive!
      # :nocov:
      module RegexpExtensions
        refine(Regexp) do
          def match?(*args)
            !match(*args).nil?
          end
        end
      end
      using(RegexpExtensions)
      # :nocov:
    end

    unless String.method_defined?(:delete_suffix!)
      module SuffixExtensions
        refine(String) do
          def delete_suffix!(suffix)
            suffix = suffix.to_s
            chomp! if frozen?
            len = suffix.length
            return unless len.positive? && index(suffix, -len)

            self[-len..-1] = ""
            self
          end
        end
      end
      using(SuffixExtensions)
    end

    SCOPES = %w[profile.read].freeze

    SERVER_METADATA = OAuth::TtlStore.new

    before "authorize"
    after "authorize"

    before "token"

    before "revoke"
    after "revoke"

    before "introspect"

    before "create_oauth_application"
    after "create_oauth_application"

    error_flash "Please authorize to continue", "require_authorization"
    error_flash "There was an error registering your oauth application", "create_oauth_application"
    notice_flash "Your oauth application has been registered", "create_oauth_application"

    notice_flash "The oauth token has been revoked", "revoke_oauth_token"

    view "authorize", "Authorize", "authorize"
    view "oauth_applications", "Oauth Applications", "oauth_applications"
    view "oauth_application", "Oauth Application", "oauth_application"
    view "new_oauth_application", "New Oauth Application", "new_oauth_application"
    view "oauth_tokens", "Oauth Tokens", "oauth_tokens"

    auth_value_method :json_response_content_type, "application/json"

    auth_value_method :oauth_grant_expires_in, 60 * 5 # 5 minutes
    auth_value_method :oauth_token_expires_in, 60 * 60 # 60 minutes
    auth_value_method :oauth_refresh_token_expires_in, 60 * 60 * 24 * 360 # 1 year
    auth_value_method :use_oauth_implicit_grant_type?, false
    auth_value_method :use_oauth_pkce?, true
    auth_value_method :use_oauth_access_type?, true

    auth_value_method :oauth_require_pkce, false
    auth_value_method :oauth_pkce_challenge_method, "S256"

    auth_value_method :oauth_valid_uri_schemes, %w[https]

    auth_value_method :oauth_scope_separator, " "

    # Application
    APPLICATION_REQUIRED_PARAMS = %w[name description scopes homepage_url redirect_uri client_secret].freeze
    auth_value_method :oauth_application_required_params, APPLICATION_REQUIRED_PARAMS

    (APPLICATION_REQUIRED_PARAMS + %w[client_id]).each do |param|
      auth_value_method :"oauth_application_#{param}_param", param
      translatable_method :"#{param}_label", param.gsub("_", " ").capitalize
    end
    button "Register", "oauth_application"
    button "Authorize", "oauth_authorize"
    button "Revoke", "oauth_token_revoke"
    button "Back to Client Application", "oauth_authorize_post"

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

    # Oauth Token Hash
    auth_value_method :oauth_tokens_token_hash_column, nil
    auth_value_method :oauth_tokens_refresh_token_hash_column, nil

    # Access Token reuse
    auth_value_method :oauth_reuse_access_token, false
    # OAuth Grants
    auth_value_method :oauth_grants_table, :oauth_grants
    auth_value_method :oauth_grants_id_column, :id
    %i[
      account_id oauth_application_id
      redirect_uri code scopes access_type
      expires_in revoked_at
      code_challenge code_challenge_method
    ].each do |column|
      auth_value_method :"oauth_grants_#{column}_column", column
    end

    auth_value_method :authorization_required_error_status, 401
    auth_value_method :invalid_oauth_response_status, 400
    auth_value_method :already_in_use_response_status, 409

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

    # Feature options
    auth_value_method :oauth_application_default_scope, SCOPES.first
    auth_value_method :oauth_application_scopes, SCOPES
    auth_value_method :oauth_token_type, "bearer"
    auth_value_method :oauth_refresh_token_protection_policy, "none" # can be: none, sender_constrained, rotation

    auth_value_method :invalid_client_message, "Invalid client"
    auth_value_method :invalid_grant_type_message, "Invalid grant type"
    auth_value_method :invalid_grant_message, "Invalid grant"
    auth_value_method :invalid_scope_message, "Invalid scope"

    auth_value_method :invalid_url_message, "Invalid URL"
    auth_value_method :unsupported_token_type_message, "Invalid token type hint"

    auth_value_method :unique_error_message, "is already in use"
    auth_value_method :null_error_message, "is not filled"
    auth_value_method :already_in_use_message, "error generating unique token"
    auth_value_method :already_in_use_error_code, "invalid_request"

    # PKCE
    auth_value_method :code_challenge_required_error_code, "invalid_request"
    auth_value_method :code_challenge_required_message, "code challenge required"
    auth_value_method :unsupported_transform_algorithm_error_code, "invalid_request"
    auth_value_method :unsupported_transform_algorithm_message, "transform algorithm not supported"

    # METADATA
    auth_value_method :oauth_metadata_service_documentation, nil
    auth_value_method :oauth_metadata_ui_locales_supported, nil
    auth_value_method :oauth_metadata_op_policy_uri, nil
    auth_value_method :oauth_metadata_op_tos_uri, nil

    # Resource Server params
    # Only required to use if the plugin is to be used in a resource server
    auth_value_method :is_authorization_server?, true

    auth_value_method :oauth_unique_id_generation_retries, 3

    auth_value_methods(
      :fetch_access_token,
      :oauth_unique_id_generator,
      :secret_matches?,
      :secret_hash,
      :generate_token_hash,
      :authorization_server_url,
      :before_introspection_request,
      :require_authorizable_account,
      :oauth_tokens_unique_columns
    )

    auth_value_methods(:only_json?)

    auth_value_method :json_request_regexp, %r{\bapplication/(?:vnd\.api\+)?json\b}i

    # /token
    route(:token) do |r|
      next unless is_authorization_server?

      before_token_route
      require_oauth_application

      r.post do
        catch_error do
          validate_oauth_token_params

          oauth_token = nil
          transaction do
            before_token
            oauth_token = create_oauth_token
          end

          json_response_success(json_access_token_payload(oauth_token))
        end

        throw_json_response_error(invalid_oauth_response_status, "invalid_request")
      end
    end

    # /introspect
    route(:introspect) do |r|
      next unless is_authorization_server?

      before_introspect_route

      r.post do
        catch_error do
          validate_oauth_introspect_params

          before_introspect
          oauth_token = case param("token_type_hint")
                        when "access_token"
                          oauth_token_by_token(param("token"))
                        when "refresh_token"
                          oauth_token_by_refresh_token(param("token"))
                        else
                          oauth_token_by_token(param("token")) || oauth_token_by_refresh_token(param("token"))
                        end

          if oauth_application
            redirect_response_error("invalid_request") if oauth_token && !token_from_application?(oauth_token, oauth_application)
          elsif oauth_token
            @oauth_application = db[oauth_applications_table].where(oauth_applications_id_column =>
              oauth_token[oauth_tokens_oauth_application_id_column]).first
          end

          json_response_success(json_token_introspect_payload(oauth_token))
        end

        throw_json_response_error(invalid_oauth_response_status, "invalid_request")
      end
    end

    # /revoke
    route(:revoke) do |r|
      next unless is_authorization_server?

      before_revoke_route
      require_oauth_application

      r.post do
        catch_error do
          validate_oauth_revoke_params

          oauth_token = nil
          transaction do
            before_revoke
            oauth_token = revoke_oauth_token
            after_revoke
          end

          if accepts_json?
            json_response_success \
              "token" => oauth_token[oauth_tokens_token_column],
              "refresh_token" => oauth_token[oauth_tokens_refresh_token_column],
              "revoked_at" => convert_timestamp(oauth_token[oauth_tokens_revoked_at_column])
          else
            set_notice_flash revoke_oauth_token_notice_flash
            redirect request.referer || "/"
          end
        end

        redirect_response_error("invalid_request", request.referer || "/")
      end
    end

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
        redirect_url = URI.parse(redirect_uri)

        params, mode = transaction do
          before_authorize
          do_authorize
        end

        case mode
        when "query"
          params = params.map { |k, v| "#{k}=#{v}" }
          params << redirect_url.query if redirect_url.query
          redirect_url.query = params.join("&")
          redirect(redirect_url.to_s)
        when "fragment"
          params = params.map { |k, v| "#{k}=#{v}" }
          params << redirect_url.query if redirect_url.query
          redirect_url.fragment = params.join("&")
          redirect(redirect_url.to_s)
        when "form_post"
          scope.view layout: false, inline: <<-FORM
<html>
  <head><title>Authorized</title></head>
  <body onload="javascript:document.forms[0].submit()">
    <form method="post" action="#{redirect_uri.to_s}">
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
        end
      end
    end

    def oauth_server_metadata(issuer = nil)
      request.on(".well-known") do
        request.on("oauth-authorization-server") do
          request.get do
            json_response_success(oauth_server_metadata_body(issuer), true)
          end
        end
      end
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
          next unless oauth_application

          scope.instance_variable_set(:@oauth_application, oauth_application)

          request.is do
            request.get do
              oauth_application_view
            end
          end

          request.on(oauth_tokens_path) do
            oauth_tokens = db[oauth_tokens_table].where(oauth_tokens_oauth_application_id_column => id)
            scope.instance_variable_set(:@oauth_tokens, oauth_tokens)
            request.get do
              oauth_tokens_view
            end
          end
        end

        request.get do
          scope.instance_variable_set(:@oauth_applications, db[oauth_applications_table])
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
      when token_path, introspect_path
        false
      when revoke_path
        !json_request?
      when authorize_path, %r{/#{oauth_applications_path}}
        only_json? ? false : super
      else
        super
      end
    end

    # Overrides logged_in?, so that a valid authorization token also authnenticates a request
    def logged_in?
      super || authorization_token
    end

    def accepts_json?
      return true if only_json?

      (accept = request.env["HTTP_ACCEPT"]) && accept =~ json_request_regexp
    end

    unless method_defined?(:json_request?)
      # copied from the jwt feature
      def json_request?
        return @json_request if defined?(@json_request)

        @json_request = request.content_type =~ json_request_regexp
      end
    end

    def initialize(scope)
      @scope = scope
    end

    def scopes
      scope = request.params["scope"]
      case scope
      when Array
        scope
      when String
        scope.split(" ")
      when nil
        [oauth_application_default_scope]
      end
    end

    def redirect_uri
      param_or_nil("redirect_uri") || begin
        return unless oauth_application

        redirect_uris = oauth_application[oauth_applications_redirect_uri_column].split(" ")
        redirect_uris.size == 1 ? redirect_uris.first : nil
      end
    end

    def oauth_application
      return @oauth_application if defined?(@oauth_application)

      @oauth_application = begin
        client_id = param_or_nil("client_id")

        return unless client_id

        db[oauth_applications_table].filter(oauth_applications_client_id_column => client_id).first
      end
    end

    def fetch_access_token
      value = request.env["HTTP_AUTHORIZATION"]

      return unless value

      scheme, token = value.split(" ", 2)

      return unless scheme.downcase == oauth_token_type

      return if token.empty?

      token
    end

    def authorization_token
      return @authorization_token if defined?(@authorization_token)

      # check if there is a token
      bearer_token = fetch_access_token

      return unless bearer_token

      # check if token has not expired
      # check if token has been revoked
      @authorization_token = oauth_token_by_token(bearer_token)
    end

    def require_oauth_authorization(*scopes)
      token_scopes = if is_authorization_server?
                       authorization_required unless authorization_token

                       scopes << oauth_application_default_scope if scopes.empty?

                       authorization_token[oauth_tokens_scopes_column].split(oauth_scope_separator)
                     else
                       bearer_token = fetch_access_token

                       authorization_required unless bearer_token

                       scopes << oauth_application_default_scope if scopes.empty?

                       # where in resource server, NOT the authorization server.
                       payload = introspection_request("access_token", bearer_token)

                       authorization_required unless payload["active"]

                       payload["scope"].split(oauth_scope_separator)
                     end

      authorization_required unless scopes.any? { |scope| token_scopes.include?(scope) }
    end

    def post_configure
      super
      self.class.__send__(:include, Rodauth::OAuth::ExtendDatabase(db))

      # Check whether we can reutilize db entries for the same account / application pair
      one_oauth_token_per_account = begin
        db.indexes(oauth_tokens_table).values.any? do |definition|
          definition[:unique] &&
            definition[:columns] == oauth_tokens_unique_columns
        end
      end
      self.class.send(:define_method, :__one_oauth_token_per_account) { one_oauth_token_per_account }
    end

    def use_date_arithmetic?
      true
    end

    private

    def rescue_from_uniqueness_error(&block)
      retries = oauth_unique_id_generation_retries
      begin
        transaction(savepoint: :only, &block)
      rescue Sequel::UniqueConstraintViolation
        redirect_response_error("already_in_use") if retries.zero?
        retries -= 1
        retry
      end
    end

    # OAuth Token Unique/Reuse
    def oauth_tokens_unique_columns
      [
        oauth_tokens_oauth_application_id_column,
        oauth_tokens_account_id_column,
        oauth_tokens_scopes_column
      ]
    end

    def authorization_server_url
      base_url
    end

    def authorization_server_metadata
      auth_url = URI(authorization_server_url)

      server_metadata = SERVER_METADATA[auth_url]

      return server_metadata if server_metadata

      SERVER_METADATA.set(auth_url) do
        http = Net::HTTP.new(auth_url.host, auth_url.port)
        http.use_ssl = auth_url.scheme == "https"

        request = Net::HTTP::Get.new("/.well-known/oauth-authorization-server")
        request["accept"] = json_response_content_type
        response = http.request(request)
        authorization_required unless response.code.to_i == 200

        # time-to-live
        ttl = if response.key?("cache-control")
                cache_control = response["cache-control"]
                cache_control[/max-age=(\d+)/, 1].to_i
              elsif response.key?("expires")
                Time.parse(response["expires"]).to_i - Time.now.to_i
              end

        [JSON.parse(response.body, symbolize_names: true), ttl]
      end
    end

    def introspection_request(token_type_hint, token)
      auth_url = URI(authorization_server_url)
      http = Net::HTTP.new(auth_url.host, auth_url.port)
      http.use_ssl = auth_url.scheme == "https"

      request = Net::HTTP::Post.new(introspect_path)
      request["content-type"] = json_response_content_type
      request["accept"] = json_response_content_type
      request.body = JSON.dump({ "token_type_hint" => token_type_hint, "token" => token })

      before_introspection_request(request)
      response = http.request(request)
      authorization_required unless response.code.to_i == 200

      JSON.parse(response.body)
    end

    def before_introspection_request(request); end

    def template_path(page)
      path = File.join(File.dirname(__FILE__), "../../../templates", "#{page}.str")
      return super unless File.exist?(path)

      path
    end

    # to be used internally. Same semantics as require account, must:
    # fetch an authorization basic header
    # parse client id and secret
    #
    def require_oauth_application
      # get client credenntials
      client_id = client_secret = nil

      # client_secret_basic
      if (token = ((v = request.env["HTTP_AUTHORIZATION"]) && v[/\A *Basic (.*)\Z/, 1]))
        client_id, client_secret = Base64.decode64(token).split(/:/, 2)
      else
        client_id = param_or_nil("client_id")
        client_secret = param_or_nil("client_secret")
      end

      authorization_required unless client_id

      @oauth_application = db[oauth_applications_table].where(oauth_applications_client_id_column => client_id).first

      # skip if using pkce
      return if @oauth_application && use_oauth_pkce? && param_or_nil("code_verifier")

      authorization_required unless @oauth_application && secret_matches?(@oauth_application, client_secret)
    end

    def secret_matches?(oauth_application, secret)
      BCrypt::Password.new(oauth_application[oauth_applications_client_secret_column]) == secret
    end

    def secret_hash(secret)
      password_hash(secret)
    end

    def oauth_unique_id_generator
      SecureRandom.urlsafe_base64(32)
    end

    def generate_token_hash(token)
      Base64.urlsafe_encode64(Digest::SHA256.digest(token))
    end

    def token_from_application?(oauth_token, oauth_application)
      oauth_token[oauth_tokens_oauth_application_id_column] == oauth_application[oauth_applications_id_column]
    end

    unless method_defined?(:password_hash)
      # From login_requirements_base feature

      def password_hash(password)
        BCrypt::Password.create(password, cost: BCrypt::Engine::DEFAULT_COST)
      end
    end

    def generate_oauth_token(params = {}, should_generate_refresh_token = true)
      create_params = {
        oauth_grants_expires_in_column => Sequel.date_add(Sequel::CURRENT_TIMESTAMP, seconds: oauth_token_expires_in)
      }.merge(params)

      rescue_from_uniqueness_error do
        token = oauth_unique_id_generator

        if oauth_tokens_token_hash_column
          create_params[oauth_tokens_token_hash_column] = generate_token_hash(token)
        else
          create_params[oauth_tokens_token_column] = token
        end

        refresh_token = nil
        if should_generate_refresh_token
          refresh_token = oauth_unique_id_generator

          if oauth_tokens_refresh_token_hash_column
            create_params[oauth_tokens_refresh_token_hash_column] = generate_token_hash(refresh_token)
          else
            create_params[oauth_tokens_refresh_token_column] = refresh_token
          end
        end
        oauth_token = _generate_oauth_token(create_params)
        oauth_token[oauth_tokens_token_column] = token
        oauth_token[oauth_tokens_refresh_token_column] = refresh_token if refresh_token
        oauth_token
      end
    end

    def _generate_oauth_token(params = {})
      ds = db[oauth_tokens_table]

      if __one_oauth_token_per_account

        token = __insert_or_update_and_return__(
          ds,
          oauth_tokens_id_column,
          oauth_tokens_unique_columns,
          params,
          Sequel.expr(Sequel[oauth_tokens_table][oauth_tokens_expires_in_column]) > Sequel::CURRENT_TIMESTAMP,
          ([oauth_tokens_token_column, oauth_tokens_refresh_token_column] if oauth_reuse_access_token)
        )

        # if the previous operation didn't return a row, it means that the conditions
        # invalidated the update, and the existing token is still valid.
        token || ds.where(
          oauth_tokens_account_id_column => params[oauth_tokens_account_id_column],
          oauth_tokens_oauth_application_id_column => params[oauth_tokens_oauth_application_id_column]
        ).first
      else
        if oauth_reuse_access_token
          unique_conds = Hash[oauth_tokens_unique_columns.map { |column| [column, params[column]] }]
          valid_token = ds.where(Sequel.expr(Sequel[oauth_tokens_table][oauth_tokens_expires_in_column]) > Sequel::CURRENT_TIMESTAMP)
                          .where(unique_conds).first
          return valid_token if valid_token
        end
        __insert_and_return__(ds, oauth_tokens_id_column, params)
      end
    end

    def oauth_token_by_token(token)
      ds = db[oauth_tokens_table]

      ds = if oauth_tokens_token_hash_column
             ds.where(oauth_tokens_token_hash_column => generate_token_hash(token))
           else
             ds.where(oauth_tokens_token_column => token)
           end

      ds.where(Sequel[oauth_tokens_expires_in_column] >= Sequel::CURRENT_TIMESTAMP)
        .where(oauth_tokens_revoked_at_column => nil).first
    end

    def oauth_token_by_refresh_token(token, revoked: false)
      ds = db[oauth_tokens_table]
      #
      # filter expired refresh tokens out.
      # an expired refresh token is a token whose access token expired for a period longer than the
      # refresh token expiration period.
      #
      ds = ds.where(Sequel.date_add(oauth_tokens_expires_in_column, seconds: oauth_refresh_token_expires_in) >= Sequel::CURRENT_TIMESTAMP)

      ds = if oauth_tokens_refresh_token_hash_column
             ds.where(oauth_tokens_refresh_token_hash_column => generate_token_hash(token))
           else
             ds.where(oauth_tokens_refresh_token_column => token)
           end

      ds = ds.where(oauth_tokens_revoked_at_column => nil) unless revoked

      ds.first
    end

    def json_access_token_payload(oauth_token)
      payload = {
        "access_token" => oauth_token[oauth_tokens_token_column],
        "token_type" => oauth_token_type,
        "expires_in" => oauth_token_expires_in
      }
      payload["refresh_token"] = oauth_token[oauth_tokens_refresh_token_column] if oauth_token[oauth_tokens_refresh_token_column]
      payload
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

    # Authorize
    def require_authorizable_account
      require_account
    end

    def validate_oauth_grant_params
      redirect_response_error("invalid_request", request.referer || default_redirect) unless oauth_application && check_valid_redirect_uri?

      unless oauth_application && check_valid_redirect_uri? && check_valid_access_type? &&
             check_valid_approval_prompt? && check_valid_response_type?
        redirect_response_error("invalid_request")
      end
      redirect_response_error("invalid_scope") unless check_valid_scopes?

      if (response_mode = param_or_nil("response_mode")) && response_mode != "form_post"
        redirect_response_error("invalid_request")
      end
      validate_pkce_challenge_params if use_oauth_pkce?
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
        oauth_grants_account_id_column => account_id,
        oauth_grants_oauth_application_id_column => oauth_application[oauth_applications_id_column],
        oauth_grants_redirect_uri_column => redirect_uri,
        oauth_grants_expires_in_column => Sequel.date_add(Sequel::CURRENT_TIMESTAMP, seconds: oauth_grant_expires_in),
        oauth_grants_scopes_column => scopes.join(oauth_scope_separator)
      )

      # Access Type flow
      if use_oauth_access_type? && (access_type = param_or_nil("access_type"))
        create_params[oauth_grants_access_type_column] = access_type
      end

      # PKCE flow
      if use_oauth_pkce? && (code_challenge = param_or_nil("code_challenge"))
        code_challenge_method = param_or_nil("code_challenge_method")

        create_params[oauth_grants_code_challenge_column] = code_challenge
        create_params[oauth_grants_code_challenge_method_column] = code_challenge_method
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
      when "token"
        redirect_response_error("invalid_request") unless use_oauth_implicit_grant_type?

        response_mode ||= "fragment"
        response_params.replace(_do_authorize_token)
      when "code", "", nil
        response_mode ||= "query"
        response_params.replace(_do_authorize_code)
      when "none"
        response_mode ||= "none"
      end

      response_params["state"] = param("state") if param_or_nil("state")

      [response_params, response_mode]
    end

    def _do_authorize_code
      { "code" => create_oauth_grant }
    end

    def _do_authorize_token
      create_params = {
        oauth_tokens_account_id_column => account_id,
        oauth_tokens_oauth_application_id_column => oauth_application[oauth_applications_id_column],
        oauth_tokens_scopes_column => scopes
      }
      oauth_token = generate_oauth_token(create_params, false)

      json_access_token_payload(oauth_token)
    end

    # Access Tokens

    def validate_oauth_token_params
      unless (grant_type = param_or_nil("grant_type"))
        redirect_response_error("invalid_request")
      end

      case grant_type
      when "authorization_code"
        redirect_response_error("invalid_request") unless param_or_nil("code")

      when "refresh_token"
        redirect_response_error("invalid_request") unless param_or_nil("refresh_token")
      else
        redirect_response_error("invalid_request")
      end
    end

    def create_oauth_token
      case param("grant_type")
      when "authorization_code"
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
      when "refresh_token"
        # fetch potentially revoked oauth token
        oauth_token = oauth_token_by_refresh_token(param("refresh_token"), revoked: true)

        if !oauth_token
          redirect_response_error("invalid_grant")
        elsif oauth_token[oauth_tokens_revoked_at_column]
          if oauth_refresh_token_protection_policy == "rotation"
            # https://tools.ietf.org/html/draft-ietf-oauth-v2-1-00#section-6.1
            #
            # If a refresh token is compromised and subsequently used by both the attacker and the legitimate
            # client, one of them will present an invalidated refresh token, which will inform the authorization
            # server of the breach.  The authorization server cannot determine which party submitted the invalid
            # refresh token, but it will revoke the active refresh token.  This stops the attack at the cost of
            # forcing the legitimate client to obtain a fresh authorization grant.

            db[oauth_tokens_table].where(oauth_tokens_oauth_token_id_column => oauth_token[oauth_tokens_id_column])
                                  .update(oauth_tokens_revoked_at_column => Sequel::CURRENT_TIMESTAMP)
          end
          redirect_response_error("invalid_grant")
        end

        update_params = {
          oauth_tokens_oauth_application_id_column => oauth_token[oauth_grants_oauth_application_id_column],
          oauth_tokens_expires_in_column => Sequel.date_add(Sequel::CURRENT_TIMESTAMP, seconds: oauth_token_expires_in)
        }
        create_oauth_token_from_token(oauth_token, update_params)
      end
    end

    def create_oauth_token_from_authorization_code(oauth_grant, create_params)
      # PKCE
      if use_oauth_pkce?
        if oauth_grant[oauth_grants_code_challenge_column]
          code_verifier = param_or_nil("code_verifier")

          redirect_response_error("invalid_request") unless code_verifier && check_valid_grant_challenge?(oauth_grant, code_verifier)
        elsif oauth_require_pkce
          redirect_response_error("code_challenge_required")
        end
      end

      # revoke oauth grant
      db[oauth_grants_table].where(oauth_grants_id_column => oauth_grant[oauth_grants_id_column])
                            .update(oauth_grants_revoked_at_column => Sequel::CURRENT_TIMESTAMP)

      should_generate_refresh_token = !use_oauth_access_type? ||
                                      oauth_grant[oauth_grants_access_type_column] == "offline"

      generate_oauth_token(create_params, should_generate_refresh_token)
    end

    def create_oauth_token_from_token(oauth_token, update_params)
      redirect_response_error("invalid_grant") unless token_from_application?(oauth_token, oauth_application)

      rescue_from_uniqueness_error do
        oauth_tokens_ds = db[oauth_tokens_table]
        token = oauth_unique_id_generator

        if oauth_tokens_token_hash_column
          update_params[oauth_tokens_token_hash_column] = generate_token_hash(token)
        else
          update_params[oauth_tokens_token_column] = token
        end

        oauth_token = if oauth_refresh_token_protection_policy == "rotation"
                        insert_params = {
                          **update_params,
                          oauth_tokens_oauth_token_id_column => oauth_token[oauth_tokens_id_column],
                          oauth_tokens_scopes_column => oauth_token[oauth_tokens_scopes_column]
                        }

                        # revoke the refresh token
                        oauth_tokens_ds.where(oauth_tokens_id_column => oauth_token[oauth_tokens_id_column])
                                       .update(oauth_tokens_revoked_at_column => Sequel::CURRENT_TIMESTAMP)

                        insert_params[oauth_tokens_oauth_token_id_column] = oauth_token[oauth_tokens_id_column]
                        __insert_and_return__(oauth_tokens_ds, oauth_tokens_id_column, insert_params)
                      else
                        # includes none
                        ds = oauth_tokens_ds.where(oauth_tokens_id_column => oauth_token[oauth_tokens_id_column])
                        __update_and_return__(ds, update_params)
                      end

        oauth_token[oauth_tokens_token_column] = token
        oauth_token
      end
    end

    TOKEN_HINT_TYPES = %w[access_token refresh_token].freeze

    # Token introspect

    def validate_oauth_introspect_params
      # check if valid token hint type
      if param_or_nil("token_type_hint") && !TOKEN_HINT_TYPES.include?(param("token_type_hint"))
        redirect_response_error("unsupported_token_type")
      end

      redirect_response_error("invalid_request") unless param_or_nil("token")
    end

    def json_token_introspect_payload(token)
      return { active: false } unless token

      {
        active: true,
        scope: token[oauth_tokens_scopes_column],
        client_id: oauth_application[oauth_applications_client_id_column],
        # username
        token_type: oauth_token_type
      }
    end

    # Token revocation

    def validate_oauth_revoke_params
      # check if valid token hint type
      if param_or_nil("token_type_hint") && !TOKEN_HINT_TYPES.include?(param("token_type_hint"))
        redirect_response_error("unsupported_token_type")
      end

      redirect_response_error("invalid_request") unless param_or_nil("token")
    end

    def revoke_oauth_token
      token = param("token")

      oauth_token = if param("token_type_hint") == "refresh_token"
                      oauth_token_by_refresh_token(token)
                    else
                      oauth_token_by_token(token)
                    end

      redirect_response_error("invalid_request") unless oauth_token

      redirect_response_error("invalid_request") unless token_from_application?(oauth_token, oauth_application)

      update_params = { oauth_tokens_revoked_at_column => Sequel::CURRENT_TIMESTAMP }

      ds = db[oauth_tokens_table].where(oauth_tokens_id_column => oauth_token[oauth_tokens_id_column])

      oauth_token = __update_and_return__(ds, update_params)

      oauth_token[oauth_tokens_token_column] = token
      oauth_token

      # If the particular
      # token is a refresh token and the authorization server supports the
      # revocation of access tokens, then the authorization server SHOULD
      # also invalidate all access tokens based on the same authorization
      # grant
      #
      # we don't need to do anything here, as we revalidate existing tokens
    end

    # Response helpers

    def redirect_response_error(error_code, redirect_url = redirect_uri || request.referer || default_redirect)
      if accepts_json?
        status_code = if respond_to?(:"#{error_code}_response_status")
                        send(:"#{error_code}_response_status")
                      else
                        invalid_oauth_response_status
                      end

        throw_json_response_error(status_code, error_code)
      else
        redirect_url = URI.parse(redirect_url)
        query_params = []

        query_params << if respond_to?(:"#{error_code}_error_code")
                          "error=#{send(:"#{error_code}_error_code")}"
                        else
                          "error=#{error_code}"
                        end

        if respond_to?(:"#{error_code}_message")
          message = send(:"#{error_code}_message")
          query_params << ["error_description=#{CGI.escape(message)}"]
        end

        query_params << redirect_url.query if redirect_url.query
        redirect_url.query = query_params.join("&")
        redirect(redirect_url.to_s)
      end
    end

    def json_response_success(body, cache = false)
      response.status = 200
      response["Content-Type"] ||= json_response_content_type
      if cache
        # defaulting to 1-day for everyone, for now at least
        max_age = 60 * 60 * 24
        response["Cache-Control"] = "private, max-age=#{max_age}"
      else
        response["Cache-Control"] = "no-store"
        response["Pragma"] = "no-cache"
      end
      json_payload = _json_response_body(body)
      response.write(json_payload)
      request.halt
    end

    def throw_json_response_error(status, error_code)
      set_response_error_status(status)
      code = if respond_to?(:"#{error_code}_error_code")
               send(:"#{error_code}_error_code")
             else
               error_code
             end
      payload = { "error" => code }
      payload["error_description"] = send(:"#{error_code}_message") if respond_to?(:"#{error_code}_message")
      json_payload = _json_response_body(payload)
      response["Content-Type"] ||= json_response_content_type
      response["WWW-Authenticate"] = oauth_token_type.upcase if status == 401
      response.write(json_payload)
      request.halt
    end

    unless method_defined?(:_json_response_body)
      def _json_response_body(hash)
        if request.respond_to?(:convert_to_json)
          request.send(:convert_to_json, hash)
        else
          JSON.dump(hash)
        end
      end
    end

    def authorization_required
      if accepts_json?
        throw_json_response_error(authorization_required_error_status, "invalid_client")
      else
        set_redirect_error_flash(require_authorization_error_flash)
        redirect(authorize_path)
      end
    end

    def check_valid_uri?(uri)
      URI::DEFAULT_PARSER.make_regexp(oauth_valid_uri_schemes).match?(uri)
    end

    def check_valid_scopes?
      return false unless scopes

      (scopes - oauth_application[oauth_applications_scopes_column].split(oauth_scope_separator)).empty?
    end

    def check_valid_redirect_uri?
      oauth_application[oauth_applications_redirect_uri_column].split(" ").include?(redirect_uri)
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

      return true if response_type.nil? || response_type == "code"

      return use_oauth_implicit_grant_type? if response_type == "token"

      false
    end

    # PKCE

    def validate_pkce_challenge_params
      if param_or_nil("code_challenge")

        challenge_method = param_or_nil("code_challenge_method")
        redirect_response_error("code_challenge_required") unless oauth_pkce_challenge_method == challenge_method
      else
        return unless oauth_require_pkce

        redirect_response_error("code_challenge_required")
      end
    end

    def check_valid_grant_challenge?(grant, verifier)
      challenge = grant[oauth_grants_code_challenge_column]

      case grant[oauth_grants_code_challenge_method_column]
      when "plain"
        challenge == verifier
      when "S256"
        generated_challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(verifier))
        generated_challenge.delete_suffix!("=") while generated_challenge.end_with?("=")

        challenge == generated_challenge
      else
        redirect_response_error("unsupported_transform_algorithm")
      end
    end

    # Server metadata

    def oauth_server_metadata_body(path)
      issuer = base_url
      issuer += "/#{path}" if path

      responses_supported = %w[code]
      response_modes_supported = %w[query]
      grant_types_supported = %w[authorization_code]

      if use_oauth_implicit_grant_type?
        responses_supported << "token"
        response_modes_supported << "fragment"
        grant_types_supported << "implicit"
      end

      {
        issuer: issuer,
        authorization_endpoint: authorize_url,
        token_endpoint: token_url,
        registration_endpoint: route_url(oauth_applications_path),
        scopes_supported: oauth_application_scopes,
        response_types_supported: responses_supported,
        response_modes_supported: response_modes_supported,
        grant_types_supported: grant_types_supported,
        token_endpoint_auth_methods_supported: %w[client_secret_basic client_secret_post],
        service_documentation: oauth_metadata_service_documentation,
        ui_locales_supported: oauth_metadata_ui_locales_supported,
        op_policy_uri: oauth_metadata_op_policy_uri,
        op_tos_uri: oauth_metadata_op_tos_uri,
        revocation_endpoint: revoke_url,
        revocation_endpoint_auth_methods_supported: nil, # because it's client_secret_basic
        introspection_endpoint: introspect_url,
        introspection_endpoint_auth_methods_supported: %w[client_secret_basic],
        code_challenge_methods_supported: (use_oauth_pkce? ? oauth_pkce_challenge_method : nil)
      }
    end
  end
end
