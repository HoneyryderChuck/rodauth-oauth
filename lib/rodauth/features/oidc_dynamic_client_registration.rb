# frozen_string_literal: true

module Rodauth
  Feature.define(:oidc_dynamic_client_registration, :OidcDynamicClientRegistration) do
    depends :oauth_dynamic_client_registration, :oidc

    auth_value_method :oauth_applications_application_type_column, :application_type

    private

    def registration_metadata
      openid_configuration_body
    end

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
      elsif (value = @oauth_application_params[oauth_applications_subject_type_column])
        unless %w[pairwise public].include?(value)
          register_throw_json_response_error("invalid_client_metadata", register_invalid_param_message("subject_type"))
        end
      elsif (value = @oauth_application_params[oauth_applications_id_token_signed_response_alg_column])
        if value == "none"
          # The value none MUST NOT be used as the ID Token alg value unless the Client uses only Response Types
          # that return no ID Token from the Authorization Endpoint
          response_types = @oauth_application_params[oauth_applications_response_types_column]
          if response_types && response_types.include?("id_token")
            register_throw_json_response_error("invalid_client_metadata", register_invalid_param_message("id_token_signed_response_alg"))
          end
        elsif !oauth_jwt_algorithms_supported.include?(value)
          register_throw_json_response_error("invalid_client_metadata", register_invalid_param_message("id_token_signed_response_alg"))
        end
      elsif (value = @oauth_application_params[oauth_applications_id_token_encrypted_response_alg_column])
        unless oauth_jwt_jwe_algorithms_supported.include?(value)
          register_throw_json_response_error("invalid_client_metadata", register_invalid_param_message("id_token_encrypted_response_alg"))
        end
      elsif (value = @oauth_application_params[oauth_applications_id_token_encrypted_response_enc_column])
        unless oauth_jwt_jwe_encryption_methods_supported.include?(value)
          register_throw_json_response_error("invalid_client_metadata", register_invalid_param_message("id_token_encrypted_response_enc"))
        end
      elsif (value = @oauth_application_params[oauth_applications_userinfo_signed_response_alg_column])
        unless oauth_jwt_algorithms_supported.include?(value)
          register_throw_json_response_error("invalid_client_metadata", register_invalid_param_message("userinfo_signed_response_alg"))
        end
      elsif (value = @oauth_application_params[oauth_applications_userinfo_encrypted_response_alg_column])
        unless oauth_jwt_jwe_algorithms_supported.include?(value)
          register_throw_json_response_error("invalid_client_metadata", register_invalid_param_message("userinfo_encrypted_response_alg"))
        end
      elsif (value = @oauth_application_params[oauth_applications_userinfo_encrypted_response_enc_column])
        unless oauth_jwt_jwe_encryption_methods_supported.include?(value)
          register_throw_json_response_error("invalid_client_metadata", register_invalid_param_message("userinfo_encrypted_response_enc"))
        end
      elsif (value = @oauth_application_params[oauth_applications_request_object_signing_alg_column])
        unless oauth_jwt_algorithms_supported.include?(value)
          register_throw_json_response_error("invalid_client_metadata", register_invalid_param_message("request_object_signing_alg"))
        end
      elsif (value = @oauth_application_params[oauth_applications_request_object_encryption_alg_column])
        unless oauth_jwt_jwe_algorithms_supported.include?(value)
          register_throw_json_response_error("invalid_client_metadata", register_invalid_param_message("request_object_encryption_alg"))
        end
      elsif (value = @oauth_application_params[oauth_applications_request_object_encryption_enc_column])
        unless oauth_jwt_jwe_encryption_methods_supported.include?(value)
          register_throw_json_response_error("invalid_client_metadata", register_invalid_param_message("request_object_encryption_enc"))
        end
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
      create_params[oauth_applications_id_token_signed_response_alg_column] ||= begin
        return_params["id_token_signed_response_alg"] = oauth_jwt_algorithm
        oauth_jwt_algorithm
      end
      if create_params.key?(oauth_applications_id_token_encrypted_response_alg_column)
        create_params[oauth_applications_id_token_encrypted_response_enc_column] ||= begin
          return_params["id_token_encrypted_response_enc"] = "A128CBC-HS256"
          "A128CBC-HS256"
        end
      end
      if create_params.key?(oauth_applications_userinfo_encrypted_response_alg_column)
        create_params[oauth_applications_userinfo_encrypted_response_enc_column] ||= begin
          return_params["userinfo_encrypted_response_enc"] = "A128CBC-HS256"
          "A128CBC-HS256"
        end
      end
      if create_params.key?(oauth_applications_request_object_encryption_alg_column)
        create_params[oauth_applications_request_object_encryption_enc_column] ||= begin
          return_params["request_object_encryption_enc"] = "A128CBC-HS256"
          "A128CBC-HS256"
        end
      end

      super(return_params)
    end

    def register_invalid_application_type_message(application_type)
      "The application type '#{application_type}' is not allowed."
    end
  end
end
