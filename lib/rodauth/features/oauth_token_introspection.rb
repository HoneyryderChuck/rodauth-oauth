# frozen_string_literal: true

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

    # Token introspect

    def validate_oauth_introspect_params(token_hint_types = %w[access_token refresh_token].freeze)
      # check if valid token hint type
      if param_or_nil("token_type_hint") && !token_hint_types.include?(param("token_type_hint"))
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

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:introspection_endpoint] = introspect_url
        data[:introspection_endpoint_auth_methods_supported] = %w[client_secret_basic]
      end
    end
  end
end
