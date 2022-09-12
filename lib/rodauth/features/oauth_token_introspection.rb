# frozen_string_literal: true

require "rodauth/oauth/http_extensions"

module Rodauth
  Feature.define(:oauth_token_introspection, :OauthTokenIntrospection) do
    depends :oauth_base

    before "introspect"

    auth_value_methods(
      :before_introspection_request
    )

    # /introspect
    route(:introspect) do |r|
      next unless is_authorization_server?

      before_introspect_route
      require_oauth_application

      r.post do
        catch_error do
          validate_oauth_introspect_params

          token_type_hint = param_or_nil("token_type_hint")

          before_introspect
          oauth_grant = case token_type_hint
                        when "access_token", nil
                          if features.include?(:oauth_jwt) && oauth_jwt_access_tokens
                            jwt_decode(param("token"))
                          else
                            oauth_grant_by_token(param("token"))
                          end
                        when "refresh_token"
                          oauth_grant_by_refresh_token(param("token"))
                        end

          oauth_grant ||= oauth_grant_by_refresh_token(param("token")) if token_type_hint.nil?

          if oauth_application
            redirect_response_error("invalid_request") if oauth_grant && !grant_from_application?(oauth_grant, oauth_application)
          elsif oauth_grant
            @oauth_application = db[oauth_applications_table].where(oauth_applications_id_column =>
              oauth_grant[oauth_grants_oauth_application_id_column]).first
          end

          json_response_success(json_token_introspect_payload(oauth_grant))
        end

        throw_json_response_error(oauth_invalid_response_status, "invalid_request")
      end
    end

    # Token introspect

    def validate_oauth_introspect_params(token_hint_types = %w[access_token refresh_token].freeze)
      # check if valid token hint type
      if param_or_nil("token_type_hint") && !token_hint_types.include?(param("token_type_hint"))
        redirect_response_error("unsupported_token_type")
      end

      redirect_response_error("invalid_request") unless param_or_nil("token")
    end

    def json_token_introspect_payload(grant_or_claims)
      return { active: false } unless grant_or_claims

      if grant_or_claims["sub"]
        # JWT
        {
          active: true,
          scope: grant_or_claims["scope"],
          client_id: grant_or_claims["client_id"],
          # username
          token_type: "access_token",
          exp: grant_or_claims["exp"],
          iat: grant_or_claims["iat"],
          nbf: grant_or_claims["nbf"],
          sub: grant_or_claims["sub"],
          aud: grant_or_claims["aud"],
          iss: grant_or_claims["iss"],
          jti: grant_or_claims["jti"]
        }
      else
        {
          active: true,
          scope: grant_or_claims[oauth_grants_scopes_column],
          client_id: oauth_application[oauth_applications_client_id_column],
          # username
          token_type: oauth_token_type,
          exp: grant_or_claims[oauth_grants_expires_in_column].to_i
        }
      end
    end

    def check_csrf?
      case request.path
      when introspect_path
        false
      else
        super
      end
    end

    private

    def introspection_request(token_type_hint, token)
      introspect_url = URI("#{authorization_server_url}#{introspect_path}")

      response = http_request(introspect_url, { "token_type_hint" => token_type_hint, "token" => token },
                              &method(:before_introspection_request))

      JSON.parse(response.body)
    end

    def before_introspection_request(request); end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:introspection_endpoint] = introspect_url
        data[:introspection_endpoint_auth_methods_supported] = %w[client_secret_basic]
      end
    end
  end
end
