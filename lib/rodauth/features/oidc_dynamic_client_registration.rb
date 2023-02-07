# frozen_string_literal: true

require "rodauth/oauth"

module Rodauth
  Feature.define(:oidc_dynamic_client_registration, :OidcDynamicClientRegistration) do
    depends :oauth_dynamic_client_registration, :oidc

    auth_value_method :oauth_applications_application_type_column, :application_type

    private

    def validate_client_registration_params
      super

      if (value = @oauth_application_params[oauth_applications_application_type_column])
        case value
        when "native"
          request.params["redirect_uris"].each do |uri|
            uri = URI(uri)
            # Native Clients MUST only register redirect_uris using custom URI schemes or
            # URLs using the http: scheme with localhost as the hostname.
            case uri.scheme
            when "http"
              register_throw_json_response_error("invalid_redirect_uri", register_invalid_uri_message(uri)) unless uri.host == "localhost"
            when "https"
              register_throw_json_response_error("invalid_redirect_uri", register_invalid_uri_message(uri))
            end
          end
        when "web"
          # Web Clients using the OAuth Implicit Grant Type MUST only register URLs using the https scheme as redirect_uris;
          # they MUST NOT use localhost as the hostname.
          if request.params["grant_types"].include?("implicit")
            request.params["redirect_uris"].each do |uri|
              uri = URI(uri)
              unless uri.scheme == "https" && uri.host != "localhost"
                register_throw_json_response_error("invalid_redirect_uri", register_invalid_uri_message(uri))
              end
            end
          end
        else
          register_throw_json_response_error("invalid_client_metadata", register_invalid_application_type_message(type))
        end
      end

      if (value = @oauth_application_params[oauth_applications_sector_identifier_uri_column])
        uri = URI(value)

        unless uri.scheme == "https" || uri.host == "localhost"
          register_throw_json_response_error("invalid_redirect_uri", register_invalid_uri_message(uri))
        end
      end

      if features.include?(:oauth_jwt_secured_authorization_request)
        if (value = @oauth_application_params[oauth_applications_request_uris_column])
          if value.is_a?(Array)
            @oauth_application_params[oauth_applications_request_uris_column] = value.each do |req_uri|
              unless check_valid_uri?(req_uri)
                register_throw_json_response_error("invalid_redirect_uri", register_invalid_uri_message(req_uri))
              end
            end.join(" ")
          else
            register_throw_json_response_error("invalid_redirect_uri", register_invalid_uri_message(value))
          end
        elsif oauth_require_request_uri_registration
          register_throw_json_response_error("invalid_client_metadata", register_required_param_message("request_uris"))
        end
      end

      if (value = @oauth_application_params[oauth_applications_subject_type_column])
        unless %w[pairwise public].include?(value)
          register_throw_json_response_error("invalid_client_metadata", register_invalid_client_metadata_message("subject_type", value))
        end

        if value == "pairwise"
          sector_identifier_uri = @oauth_application_params[oauth_applications_sector_identifier_uri_column]

          if sector_identifier_uri
            response = http_request(sector_identifier_uri)
            unless response.code.to_i == 200
              register_throw_json_response_error("invalid_client_metadata",
                                                 register_invalid_param_message("sector_identifier_uri"))
            end
            uris = JSON.parse(response.body)

            if uris != @oauth_application_params[oauth_applications_redirect_uri_column].split(" ")
              register_throw_json_response_error("invalid_client_metadata", register_invalid_param_message("sector_identifier_uri"))
            end

          end
        end
      end

      if (value = @oauth_application_params[oauth_applications_id_token_signed_response_alg_column])
        if value == "none"
          # The value none MUST NOT be used as the ID Token alg value unless the Client uses only Response Types
          # that return no ID Token from the Authorization Endpoint
          response_types = @oauth_application_params[oauth_applications_response_types_column]
          if response_types && response_types.include?("id_token")
            register_throw_json_response_error("invalid_client_metadata", register_invalid_param_message("id_token_signed_response_alg"))
          end
        elsif !oauth_jwt_jws_algorithms_supported.include?(value)
          register_throw_json_response_error("invalid_client_metadata",
                                             register_invalid_client_metadata_message("id_token_signed_response_alg", value))
        end
      end

      if features.include?(:oauth_jwt_secured_authorization_request)
        if defined?(oauth_applications_request_object_signing_alg_column) &&
           (value = @oauth_application_params[oauth_applications_request_object_signing_alg_column]) &&
           !oauth_jwt_jws_algorithms_supported.include?(value) && !(value == "none" && oauth_request_object_signing_alg_allow_none)
          register_throw_json_response_error("invalid_client_metadata",
                                             register_invalid_client_metadata_message("request_object_signing_alg", value))
        end

        if defined?(oauth_applications_request_object_encryption_alg_column) &&
           (value = @oauth_application_params[oauth_applications_request_object_encryption_alg_column]) &&
           !oauth_jwt_jwe_algorithms_supported.include?(value)
          register_throw_json_response_error("invalid_client_metadata",
                                             register_invalid_client_metadata_message("request_object_encryption_alg", value))
        end

        if defined?(oauth_applications_request_object_encryption_enc_column) &&
           (value = @oauth_application_params[oauth_applications_request_object_encryption_enc_column]) &&
           !oauth_jwt_jwe_encryption_methods_supported.include?(value)
          register_throw_json_response_error("invalid_client_metadata",
                                             register_invalid_client_metadata_message("request_object_encryption_enc", value))
        end
      end

      if features.include?(:oidc_rp_initiated_logout) && (defined?(oauth_applications_post_logout_redirect_uris_column) &&
           (value = @oauth_application_params[oauth_applications_post_logout_redirect_uris_column]))
        if value.is_a?(Array)
          @oauth_application_params[oauth_applications_post_logout_redirect_uris_column] = value.each do |redirect_uri|
            unless check_valid_uri?(redirect_uri)
              register_throw_json_response_error("invalid_client_metadata", register_invalid_uri_message(redirect_uri))
            end
          end.join(" ")
        else
          register_throw_json_response_error("invalid_client_metadata", register_invalid_uri_message(value))
        end
      end

      if (value = @oauth_application_params[oauth_applications_id_token_encrypted_response_alg_column]) &&
         !oauth_jwt_jwe_algorithms_supported.include?(value)
        register_throw_json_response_error("invalid_client_metadata",
                                           register_invalid_client_metadata_message("id_token_encrypted_response_alg", value))
      end

      if (value = @oauth_application_params[oauth_applications_id_token_encrypted_response_enc_column]) &&
         !oauth_jwt_jwe_encryption_methods_supported.include?(value)
        register_throw_json_response_error("invalid_client_metadata",
                                           register_invalid_client_metadata_message("id_token_encrypted_response_enc", value))
      end

      if (value = @oauth_application_params[oauth_applications_userinfo_signed_response_alg_column]) &&
         !oauth_jwt_jws_algorithms_supported.include?(value)
        register_throw_json_response_error("invalid_client_metadata",
                                           register_invalid_client_metadata_message("userinfo_signed_response_alg", value))
      end

      if (value = @oauth_application_params[oauth_applications_userinfo_encrypted_response_alg_column]) &&
         !oauth_jwt_jwe_algorithms_supported.include?(value)
        register_throw_json_response_error("invalid_client_metadata",
                                           register_invalid_client_metadata_message("userinfo_encrypted_response_alg", value))
      end

      if (value = @oauth_application_params[oauth_applications_userinfo_encrypted_response_enc_column]) &&
         !oauth_jwt_jwe_encryption_methods_supported.include?(value)
        register_throw_json_response_error("invalid_client_metadata",
                                           register_invalid_client_metadata_message("userinfo_encrypted_response_enc", value))
      end
    end

    def validate_client_registration_response_type(response_type, grant_types)
      case response_type
      when "id_token"
        unless grant_types.include?("implicit")
          register_throw_json_response_error("invalid_client_metadata",
                                             register_invalid_response_type_for_grant_type_message(response_type, "implicit"))
        end
      else
        super
      end
    end

    def do_register(return_params = request.params.dup)
      # set defaults

      create_params = @oauth_application_params

      create_params[oauth_applications_application_type_column] ||= begin
        return_params["application_type"] = "web"
        "web"
      end
      create_params[oauth_applications_id_token_signed_response_alg_column] ||= return_params["id_token_signed_response_alg"] =
        oauth_jwt_keys.keys.first

      if create_params.key?(oauth_applications_id_token_encrypted_response_alg_column)
        create_params[oauth_applications_id_token_encrypted_response_enc_column] ||= return_params["id_token_encrypted_response_enc"] =
          "A128CBC-HS256"

      end
      if create_params.key?(oauth_applications_userinfo_encrypted_response_alg_column)
        create_params[oauth_applications_userinfo_encrypted_response_enc_column] ||= return_params["userinfo_encrypted_response_enc"] =
          "A128CBC-HS256"

      end
      if defined?(oauth_applications_request_object_encryption_alg_column) &&
         create_params.key?(oauth_applications_request_object_encryption_alg_column)
        create_params[oauth_applications_request_object_encryption_enc_column] ||= return_params["request_object_encryption_enc"] =
          "A128CBC-HS256"

      end

      super(return_params)
    end

    def register_invalid_application_type_message(application_type)
      "The application type '#{application_type}' is not allowed."
    end

    def initialize_register_params(create_params, return_params)
      super
      client_registration_token = oauth_unique_id_generator
      create_params[oauth_applications_client_registration_token_column] = secret_hash(client_registration_token)
      return_params["client_registration_token"] = client_registration_token
      return_params["client_registration_uri"] = "#{base_url}/#{client_registration_uri_route}/#{return_params['client_id']}"
    end
  end
end
