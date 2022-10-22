# frozen_string_literal: true

require "rodauth/oauth"

module Rodauth
  Feature.define(:oauth_dynamic_client_registration, :OauthDynamicClientRegistration) do
    depends :oauth_base

    before "register"

    auth_value_method :oauth_client_registration_required_params, %w[redirect_uris client_name]

    PROTECTED_APPLICATION_ATTRIBUTES = %w[account_id client_id].freeze

    # /register
    auth_server_route(:register) do |r|
      before_register_route

      validate_client_registration_params

      r.post do
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

    def validate_client_registration_params
      oauth_client_registration_required_params.each do |required_param|
        unless request.params.key?(required_param)
          register_throw_json_response_error("invalid_client_metadata", register_required_param_message(required_param))
        end
      end

      @oauth_application_params = request.params.each_with_object({}) do |(key, value), params|
        case key
        when "redirect_uris"
          if value.is_a?(Array)
            value = value.each do |uri|
              register_throw_json_response_error("invalid_redirect_uri", register_invalid_uri_message(uri)) unless check_valid_uri?(uri)
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
            grant_types = request.params["grant_types"] || oauth_grant_types_supported
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
            key = "homepage_url"
          when "jwks_uri"
            if request.params.key?("jwks")
              register_throw_json_response_error("invalid_client_metadata",
                                                 register_invalid_jwks_param_message(key, "jwks"))
            end
          end
          key = __send__(:"oauth_applications_#{key}_column")
        when "jwks"
          register_throw_json_response_error("invalid_client_metadata", register_invalid_param_message(value)) unless value.is_a?(Hash)
          if request.params.key?("jwks_uri")
            register_throw_json_response_error("invalid_client_metadata",
                                               register_invalid_jwks_param_message(key, "jwks_uri"))
          end

          key = oauth_applications_jwks_column
          value = JSON.dump(value)
        when "scope"
          scopes = value.split(" ") - oauth_application_scopes
          register_throw_json_response_error("invalid_client_metadata", register_invalid_scopes_message(value)) unless scopes.empty?
          key = oauth_applications_scopes_column
          # verify if in range
        when "contacts"
          register_throw_json_response_error("invalid_client_metadata", register_invalid_contacts_message(value)) unless value.is_a?(Array)
          value = value.join(" ")
          key = oauth_applications_contacts_column
        when "client_name"
          key = oauth_applications_name_column
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
      create_params[oauth_applications_scopes_column] ||= return_params["scopes"] = oauth_application_scopes.join(" ")
      if create_params[oauth_applications_grant_types_column] ||= begin
        return_params["grant_types"] = %w[authorization_code] # rubocop:disable Lint/AssignmentInCondition
        "authorization_code"
      end
        create_params[oauth_applications_token_endpoint_auth_method_column] ||= begin
          return_params["token_endpoint_auth_method"] = "client_secret_basic"
          "client_secret_basic"
        end
      end
      create_params[oauth_applications_response_types_column] ||= begin
        return_params["response_types"] = %w[code]
        "code"
      end
      rescue_from_uniqueness_error do
        client_id = oauth_unique_id_generator
        create_params[oauth_applications_client_id_column] = client_id
        return_params["client_id"] = client_id
        return_params["client_id_issued_at"] = Time.now.utc.iso8601
        if create_params.key?(oauth_applications_client_secret_column)
          set_client_secret(create_params, create_params[oauth_applications_client_secret_column])
          return_params.delete("client_secret")
        else
          client_secret = oauth_unique_id_generator
          set_client_secret(create_params, client_secret)
          return_params["client_secret"] = client_secret
          return_params["client_secret_expires_at"] = 0

          create_params.delete_if { |k, _| !application_columns.include?(k) }
        end
        applications_ds.insert(create_params)
      end

      return_params
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

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:registration_endpoint] = register_url
      end
    end
  end
end
