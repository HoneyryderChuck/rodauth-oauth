# frozen-string-literal: true

require "time"
require "base64"
require "securerandom"
require "net/http"

require "rodauth/oauth/ttl_store"
require "rodauth/oauth/database_extensions"

module Rodauth
  Feature.define(:oauth, :Oauth) do
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

    depends :oauth_base, :oauth_pkce, :oauth_implicit_grant, :oauth_device_grant

    SERVER_METADATA = OAuth::TtlStore.new

    before "revoke"
    after "revoke"

    before "introspect"

    before "create_oauth_application"
    after "create_oauth_application"

    error_flash "There was an error registering your oauth application", "create_oauth_application"
    notice_flash "Your oauth application has been registered", "create_oauth_application"

    notice_flash "The oauth token has been revoked", "revoke_oauth_token"
    error_flash "You are not authorized to revoke this token", "revoke_unauthorized_account"

    view "oauth_applications", "Oauth Applications", "oauth_applications"
    view "oauth_application", "Oauth Application", "oauth_application"
    view "new_oauth_application", "New Oauth Application", "new_oauth_application"
    view "oauth_application_oauth_tokens", "Oauth Application Tokens", "oauth_application_oauth_tokens"
    view "oauth_tokens", "My Oauth Tokens", "oauth_tokens"

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

    # OAuth Token
    auth_value_method :oauth_applications_oauth_tokens_path, "oauth-tokens"
    auth_value_method :oauth_tokens_path, "oauth-tokens"

    %w[token refresh_token expires_in revoked_at].each do |param|
      translatable_method :"oauth_tokens_#{param}_label", param.gsub("_", " ").capitalize
    end

    # OAuth Applications
    auth_value_method :oauth_applications_route, "oauth-applications"
    def oauth_applications_path(opts = {})
      route_path(oauth_applications_route, opts)
    end

    def oauth_applications_url(opts = {})
      route_url(oauth_applications_route, opts)
    end

    # OAuth Tokens
    auth_value_method :oauth_tokens_route, "oauth-tokens"
    def oauth_tokens_path(opts = {})
      route_path(oauth_tokens_route, opts)
    end

    def oauth_tokens_url(opts = {})
      route_url(oauth_tokens_route, opts)
    end

    auth_value_method :oauth_applications_id_pattern, Integer
    auth_value_method :oauth_tokens_id_pattern, Integer

    translatable_method :invalid_url_message, "Invalid URL"
    translatable_method :unsupported_token_type_message, "Invalid token type hint"

    translatable_method :null_error_message, "is not filled"

    # METADATA
    auth_value_method :oauth_metadata_service_documentation, nil
    auth_value_method :oauth_metadata_ui_locales_supported, nil
    auth_value_method :oauth_metadata_op_policy_uri, nil
    auth_value_method :oauth_metadata_op_tos_uri, nil

    auth_value_methods(
      :oauth_application_path,
      :before_introspection_request
    )

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

      if logged_in?
        require_account
        require_oauth_application_from_account
      else
        require_oauth_application
      end

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

    def oauth_server_metadata(issuer = nil)
      request.on(".well-known") do
        request.on("oauth-authorization-server") do
          request.get do
            json_response_success(oauth_server_metadata_body(issuer), true)
          end
        end
      end
    end

    def oauth_application_path(id)
      "#{oauth_applications_path}/#{id}"
    end

    def oauth_token_path(id)
      "#{oauth_tokens_path}/#{id}"
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

    # /oauth-tokens routes
    def oauth_tokens
      request.on(oauth_tokens_route) do
        require_account

        request.get do
          scope.instance_variable_set(:@oauth_tokens, db[oauth_tokens_table]
            .select(Sequel[oauth_tokens_table].*, Sequel[oauth_applications_table][oauth_applications_name_column])
            .join(oauth_applications_table, Sequel[oauth_tokens_table][oauth_tokens_oauth_application_id_column] =>
              Sequel[oauth_applications_table][oauth_applications_id_column])
            .where(Sequel[oauth_tokens_table][oauth_tokens_account_id_column] => account_id)
                .where(oauth_tokens_revoked_at_column => nil))
          oauth_tokens_view
        end

        request.post(oauth_tokens_id_pattern) do |id|
          db[oauth_tokens_table]
            .where(oauth_tokens_id_column => id)
            .where(oauth_tokens_account_id_column => account_id)
            .update(oauth_tokens_revoked_at_column => Sequel::CURRENT_TIMESTAMP)

          set_notice_flash revoke_oauth_token_notice_flash
          redirect oauth_tokens_path || "/"
        end
      end
    end

    def check_csrf?
      case request.path
      when token_path, introspect_path, device_authorization_path
        false
      when revoke_path
        !json_request?
      when authorize_path, oauth_applications_path
        only_json? ? false : super
      else
        super
      end
    end

    private

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
      request["content-type"] = "application/x-www-form-urlencoded"
      request["accept"] = json_response_content_type
      request.set_form_data({ "token_type_hint" => token_type_hint, "token" => token })

      before_introspection_request(request)
      response = http.request(request)
      authorization_required unless response.code.to_i == 200

      JSON.parse(response.body)
    end

    def before_introspection_request(request); end

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
        token_type: oauth_token_type,
        exp: token[oauth_tokens_expires_in_column].to_i
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

    def check_valid_uri?(uri)
      URI::DEFAULT_PARSER.make_regexp(oauth_valid_uri_schemes).match?(uri)
    end

    # Server metadata

    def oauth_server_metadata_body(path)
      issuer = base_url
      issuer += "/#{path}" if path

      responses_supported = %w[code]
      response_modes_supported = %w[query form_post]
      grant_types_supported = %w[authorization_code]

      if use_oauth_implicit_grant_type?
        responses_supported << "token"
        response_modes_supported << "fragment"
        grant_types_supported << "implicit"
      end

      payload = {
        issuer: issuer,
        authorization_endpoint: authorize_url,
        token_endpoint: token_url,
        registration_endpoint: oauth_applications_url,
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

      if use_oauth_device_code_grant_type?
        grant_types_supported << "urn:ietf:params:oauth:grant-type:device_code"
        payload[:device_authorization_endpoint] = device_authorization_url
      end

      payload
    end
  end
end
