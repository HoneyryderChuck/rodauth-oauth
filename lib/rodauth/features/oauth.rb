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

    depends :oauth_base, :oauth_pkce, :oauth_implicit_grant, :oauth_device_grant, :oauth_token_introspection, :oauth_token_revocation,
            :oauth_application_management, :oauth_token_management

    SERVER_METADATA = OAuth::TtlStore.new

    # METADATA
    auth_value_method :oauth_metadata_service_documentation, nil
    auth_value_method :oauth_metadata_ui_locales_supported, nil
    auth_value_method :oauth_metadata_op_policy_uri, nil
    auth_value_method :oauth_metadata_op_tos_uri, nil

    auth_value_methods(
      :oauth_token_path
    )

    def oauth_server_metadata(issuer = nil)
      request.on(".well-known") do
        request.on("oauth-authorization-server") do
          request.get do
            json_response_success(oauth_server_metadata_body(issuer), true)
          end
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
