# frozen_string_literal: true

require "rodauth/oauth"

module Rodauth
  Feature.define(:oauth_dynamic_client_registration, :OauthDynamicClientRegistration) do
    depends :oauth_base

    before "register"

    auth_value_method :oauth_client_registration_required_params, %w[redirect_uris client_name]
    auth_value_method :oauth_applications_registration_access_token_column, :registration_access_token
    auth_value_method :registration_client_uri_route, "register"

    PROTECTED_APPLICATION_ATTRIBUTES = %w[account_id client_id].freeze

    def load_registration_client_uri_routes
      request.on(registration_client_uri_route) do
        # CLIENT REGISTRATION URI
        request.on(String) do |client_id|
          token = (v = request.env["HTTP_AUTHORIZATION"]) && v[/\A *Bearer (.*)\Z/, 1]

          next unless token

          oauth_application = db[oauth_applications_table]
                              .where(oauth_applications_client_id_column => client_id)
                              .first
          next unless oauth_application

          authorization_required unless password_hash_match?(oauth_application[oauth_applications_registration_access_token_column], token)

          request.is do
            request.get do
              json_response_oauth_application(oauth_application)
            end
            request.on method: :put do
              %w[client_id registration_access_token registration_client_uri client_secret_expires_at
                 client_id_issued_at].each do |prohibited_param|
                if request.params.key?(prohibited_param)
                  register_throw_json_response_error("invalid_client_metadata", register_invalid_param_message(prohibited_param))
                end
              end
              validate_client_registration_params

              # if the client includes the "client_secret" field in the request, the value of this field MUST match the currently
              # issued client secret for that client.  The client MUST NOT be allowed to overwrite its existing client secret with
              # its own chosen value.
              authorization_required if request.params.key?("client_secret") && secret_matches?(oauth_application,
                                                                                                request.params["client_secret"])

              oauth_application = transaction do
                applications_ds = db[oauth_applications_table]
                __update_and_return__(applications_ds, @oauth_application_params)
              end
              json_response_oauth_application(oauth_application)
            end

            request.on method: :delete do
              applications_ds = db[oauth_applications_table]
              applications_ds.where(oauth_applications_client_id_column => client_id).delete
              response.status = 204
              response["Cache-Control"] = "no-store"
              response["Pragma"] = "no-cache"
              response.finish
            end
          end
        end
      end
    end

    # /register
    auth_server_route(:register) do |r|
      before_register_route

      r.post do
        oauth_client_registration_required_params.each do |required_param|
          unless request.params.key?(required_param)
            register_throw_json_response_error("invalid_client_metadata", register_required_param_message(required_param))
          end
        end

        validate_client_registration_params

        response_params = transaction do
          before_register
          do_register
        end

        response.status = 201
        response["Content-Type"] = json_response_content_type
        response["Cache-Control"] = "no-store"
        response["Pragma"] = "no-cache"
        response.write(_json_response_body(response_params))
      end
    end

    def check_csrf?
      case request.path
      when register_path
        false
      else
        super
      end
    end

    private

    def _before_register
      raise %{dynamic client registration requires authentication.
        Override ´before_register` to perform it.
        example:

          before_register do
            account = _account_from_login(request.env["HTTP_X_USER_EMAIL"])
            authorization_required unless account
            @oauth_application_params[:account_id] = account[:id]
          end
      }
    end

    def validate_client_registration_params(request_params = request.params)
      @oauth_application_params = request_params.each_with_object({}) do |(key, value), params|
        case key
        when "redirect_uris"
          if value.is_a?(Array)
            value = value.each do |uri|
              unless check_valid_no_fragment_uri?(uri)
                register_throw_json_response_error("invalid_redirect_uri",
                                                   register_invalid_uri_message(uri))
              end
            end.join(" ")
          else
            register_throw_json_response_error("invalid_redirect_uri", register_invalid_uri_message(value))
          end
          key = oauth_applications_redirect_uri_column
        when "token_endpoint_auth_method"
          unless oauth_token_endpoint_auth_methods_supported.include?(value)
            register_throw_json_response_error("invalid_client_metadata", register_invalid_client_metadata_message(key, value))
          end
          # verify if in range
          key = oauth_applications_token_endpoint_auth_method_column
        when "grant_types"
          if value.is_a?(Array)
            value = value.each do |grant_type|
              unless oauth_grant_types_supported.include?(grant_type)
                register_throw_json_response_error("invalid_client_metadata", register_invalid_client_metadata_message(grant_type, value))
              end
            end.join(" ")
          else
            register_throw_json_response_error("invalid_client_metadata", register_invalid_client_metadata_message(key, value))
          end
          key = oauth_applications_grant_types_column
        when "response_types"
          if value.is_a?(Array)
            grant_types = request_params["grant_types"] || %w[authorization_code]
            value = value.each do |response_type|
              unless oauth_response_types_supported.include?(response_type)
                register_throw_json_response_error("invalid_client_metadata",
                                                   register_invalid_response_type_message(response_type))
              end

              validate_client_registration_response_type(response_type, grant_types)
            end.join(" ")
          else
            register_throw_json_response_error("invalid_client_metadata", register_invalid_client_metadata_message(key, value))
          end
          key = oauth_applications_response_types_column
          # verify if in range and match grant type
        when "client_uri", "logo_uri", "tos_uri", "policy_uri", "jwks_uri"
          register_throw_json_response_error("invalid_client_metadata", register_invalid_uri_message(value)) unless check_valid_uri?(value)
          case key
          when "client_uri"
            key = oauth_applications_homepage_url_column
          when "jwks_uri"
            if request_params.key?("jwks")
              register_throw_json_response_error("invalid_client_metadata",
                                                 register_invalid_jwks_param_message(key, "jwks"))
            end
          end
          key = __send__(:"oauth_applications_#{key}_column")
        when "jwks"
          register_throw_json_response_error("invalid_client_metadata", register_invalid_param_message(value)) unless value.is_a?(Hash)
          if request_params.key?("jwks_uri")
            register_throw_json_response_error("invalid_client_metadata",
                                               register_invalid_jwks_param_message(key, "jwks_uri"))
          end

          key = oauth_applications_jwks_column
          value = JSON.dump(value)
        when "scope"
          register_throw_json_response_error("invalid_client_metadata", register_invalid_param_message(value)) unless value.is_a?(String)
          scopes = value.split(" ") - oauth_application_scopes
          register_throw_json_response_error("invalid_client_metadata", register_invalid_scopes_message(value)) unless scopes.empty?
          key = oauth_applications_scopes_column
          # verify if in range
        when "contacts"
          register_throw_json_response_error("invalid_client_metadata", register_invalid_contacts_message(value)) unless value.is_a?(Array)
          value = value.join(" ")
          key = oauth_applications_contacts_column
        when "client_name"
          register_throw_json_response_error("invalid_client_metadata", register_invalid_param_message(value)) unless value.is_a?(String)
          key = oauth_applications_name_column
        when "dpop_bound_access_tokens"
          unless respond_to?(:oauth_applications_dpop_bound_access_tokens_column)
            register_throw_json_response_error("invalid_client_metadata",
                                               register_invalid_param_message(key))
          end
          request_params[key] = value = convert_to_boolean(key, value)

          key = oauth_applications_dpop_bound_access_tokens_column
        when "require_signed_request_object"
          unless respond_to?(:oauth_applications_require_signed_request_object_column)
            register_throw_json_response_error("invalid_client_metadata",
                                               register_invalid_param_message(key))
          end
          request_params[key] = value = convert_to_boolean(key, value)

          key = oauth_applications_require_signed_request_object_column
        when "require_pushed_authorization_requests"
          unless respond_to?(:oauth_applications_require_pushed_authorization_requests_column)
            register_throw_json_response_error("invalid_client_metadata",
                                               register_invalid_param_message(key))
          end
          request_params[key] = value = convert_to_boolean(key, value)

          key = oauth_applications_require_pushed_authorization_requests_column
        when "tls_client_certificate_bound_access_tokens"
          property = :oauth_applications_tls_client_certificate_bound_access_tokens_column
          register_throw_json_response_error("invalid_client_metadata", register_invalid_param_message(key)) unless respond_to?(property)

          request_params[key] = value = convert_to_boolean(key, value)

          key = oauth_applications_tls_client_certificate_bound_access_tokens_column
        when /\Atls_client_auth_/
          unless respond_to?(:"oauth_applications_#{key}_column")
            register_throw_json_response_error("invalid_client_metadata",
                                               register_invalid_param_message(key))
          end

          #  client using the tls_client_auth authentication method MUST use exactly one of the below metadata
          # parameters to indicate the certificate subject value that the authorization server is to expect when
          # authenticating the respective client.
          if params.any? { |k, _| k.to_s.start_with?("tls_client_auth_") }
            register_throw_json_response_error("invalid_client_metadata", register_invalid_param_message(key))
          end

          key = __send__(:"oauth_applications_#{key}_column")
        else
          if respond_to?(:"oauth_applications_#{key}_column")
            if PROTECTED_APPLICATION_ATTRIBUTES.include?(key)
              register_throw_json_response_error("invalid_client_metadata", register_invalid_param_message(key))
            end
            property = :"oauth_applications_#{key}_column"
            key = __send__(property)
          elsif !db[oauth_applications_table].columns.include?(key.to_sym)
            register_throw_json_response_error("invalid_client_metadata", register_invalid_param_message(key))
          end
        end
        params[key] = value
      end
    end

    def validate_client_registration_response_type(response_type, grant_types)
      case response_type
      when "code"
        unless grant_types.include?("authorization_code")
          register_throw_json_response_error("invalid_client_metadata",
                                             register_invalid_response_type_for_grant_type_message(response_type,
                                                                                                   "authorization_code"))
        end
      when "token"
        unless grant_types.include?("implicit")
          register_throw_json_response_error("invalid_client_metadata",
                                             register_invalid_response_type_for_grant_type_message(response_type, "implicit"))
        end
      when "none"
        if grant_types.include?("implicit") || grant_types.include?("authorization_code")
          register_throw_json_response_error("invalid_client_metadata", register_invalid_response_type_message(response_type))
        end
      end
    end

    def do_register(return_params = request.params.dup)
      applications_ds = db[oauth_applications_table]
      application_columns = applications_ds.columns

      # set defaults
      create_params = @oauth_application_params

      # If omitted, an authorization server MAY register a client with a default set of scopes
      create_params[oauth_applications_scopes_column] ||= return_params["scopes"] = oauth_application_scopes.join(" ")

      # https://datatracker.ietf.org/doc/html/rfc7591#section-2
      if create_params[oauth_applications_grant_types_column] ||= begin
        # If omitted, the default behavior is that the client will use only the "authorization_code" Grant Type.
        return_params["grant_types"] = %w[authorization_code] # rubocop:disable Lint/AssignmentInCondition
        "authorization_code"
      end
        create_params[oauth_applications_token_endpoint_auth_method_column] ||= begin
          # If unspecified or omitted, the default is "client_secret_basic", denoting the HTTP Basic
          # authentication scheme as specified in Section 2.3.1 of OAuth 2.0.
          return_params["token_endpoint_auth_method"] =
            "client_secret_basic"
          "client_secret_basic"
        end
      end
      create_params[oauth_applications_response_types_column] ||= begin
        # If omitted, the default is that the client will use only the "code" response type.
        return_params["response_types"] = %w[code]
        "code"
      end
      rescue_from_uniqueness_error do
        initialize_register_params(create_params, return_params)
        create_params.delete_if { |k, _| !application_columns.include?(k) }
        applications_ds.insert(create_params)
      end

      return_params
    end

    def initialize_register_params(create_params, return_params)
      client_id = oauth_unique_id_generator
      create_params[oauth_applications_client_id_column] = client_id
      return_params["client_id"] = client_id
      return_params["client_id_issued_at"] = Time.now.utc.iso8601

      registration_access_token = oauth_unique_id_generator
      create_params[oauth_applications_registration_access_token_column] = secret_hash(registration_access_token)
      return_params["registration_access_token"] = registration_access_token
      return_params["registration_client_uri"] = "#{base_url}/#{registration_client_uri_route}/#{return_params['client_id']}"

      if create_params.key?(oauth_applications_client_secret_column)
        set_client_secret(create_params, create_params[oauth_applications_client_secret_column])
        return_params.delete("client_secret")
      else
        client_secret = oauth_unique_id_generator
        set_client_secret(create_params, client_secret)
        return_params["client_secret"] = client_secret
        return_params["client_secret_expires_at"] = 0

      end
    end

    def register_throw_json_response_error(code, message)
      throw_json_response_error(oauth_invalid_response_status, code, message)
    end

    def register_required_param_message(key)
      "The param '#{key}' is required by this server."
    end

    def register_invalid_param_message(key)
      "The param '#{key}' is not supported by this server."
    end

    def register_invalid_client_metadata_message(key, value)
      "The value '#{value}' is not supported by this server for param '#{key}'."
    end

    def register_invalid_contacts_message(contacts)
      "The contacts '#{contacts}' are not allowed by this server."
    end

    def register_invalid_uri_message(uri)
      "The '#{uri}' URL is not allowed by this server."
    end

    def register_invalid_jwks_param_message(key1, key2)
      "The param '#{key1}' cannot be accepted together with param '#{key2}'."
    end

    def register_invalid_scopes_message(scopes)
      "The given scopes (#{scopes}) are not allowed by this server."
    end

    def register_oauth_invalid_grant_type_message(grant_type)
      "The grant type #{grant_type} is not allowed by this server."
    end

    def register_invalid_response_type_message(response_type)
      "The response type #{response_type} is not allowed by this server."
    end

    def register_invalid_response_type_for_grant_type_message(response_type, grant_type)
      "The grant type '#{grant_type}' must be registered for the response " \
        "type '#{response_type}' to be allowed."
    end

    def convert_to_boolean(key, value)
      case value
      when true, false then value
      when "true" then true
      when "false" then false
      else
        register_throw_json_response_error(
          "invalid_client_metadata",
          register_invalid_param_message(key)
        )
      end
    end

    def json_response_oauth_application(oauth_application)
      params = methods.map { |k| k.to_s[/\Aoauth_applications_(\w+)_column\z/, 1] }.compact

      body = params.each_with_object({}) do |k, hash|
        next if %w[id account_id client_id client_secret cliennt_secret_hash].include?(k)

        value = oauth_application[__send__(:"oauth_applications_#{k}_column")]

        next unless value

        case k
        when "redirect_uri"
          hash["redirect_uris"] = value.split(" ")
        when "token_endpoint_auth_method", "grant_types", "response_types", "request_uris", "post_logout_redirect_uris"
          hash[k] = value.split(" ")
        when "scopes"
          hash["scope"] = value
        when "jwks"
          hash[k] = value.is_a?(String) ? JSON.parse(value) : value
        when "homepage_url"
          hash["client_uri"] = value
        when "name"
          hash["client_name"] = value
        else
          hash[k] = value
        end
      end

      response.status = 200
      response["Content-Type"] ||= json_response_content_type
      response["Cache-Control"] = "no-store"
      response["Pragma"] = "no-cache"
      json_payload = _json_response_body(body)
      return_response(json_payload)
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:registration_endpoint] = register_url
      end
    end
  end
end
