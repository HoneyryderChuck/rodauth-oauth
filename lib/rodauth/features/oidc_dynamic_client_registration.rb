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

    def register_invalid_application_type_message(application_type)
      "The application type '#{application_type}' is not allowed."
    end
  end
end
