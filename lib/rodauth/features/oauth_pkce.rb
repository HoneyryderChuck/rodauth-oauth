# frozen_string_literal: true

require "rodauth/oauth"

module Rodauth
  Feature.define(:oauth_pkce, :OauthPkce) do
    depends :oauth_authorization_code_grant

    auth_value_method :oauth_require_pkce, true
    auth_value_method :oauth_pkce_challenge_method, "S256"

    # TODO: change to false in a major version bump
    # RFC 7636 §4.2 discourages the "plain" transform: it transmits the raw code_verifier,
    # so an intercepted authorization request exposes it and defeats PKCE.
    auth_value_method :oauth_pkce_allow_plain_method, true

    auth_value_method :oauth_grants_code_challenge_column, :code_challenge
    auth_value_method :oauth_grants_code_challenge_method_column, :code_challenge_method

    auth_value_method :oauth_code_challenge_required_error_code, "invalid_request"
    translatable_method :oauth_code_challenge_required_message, "code challenge required"
    auth_value_method :oauth_unsupported_transform_algorithm_error_code, "invalid_request"
    translatable_method :oauth_unsupported_transform_algorithm_message, "transform algorithm not supported"

    def authorize_form_params
      super.tap do |params|
        %w[code_challenge code_challenge_method].each do |param_name|
          if (param_value = param_or_nil(param_name))
            params << { "name" => param_name, "value" => param_value, "type" => "hidden" }
          end
        end
      end
    end

    private

    def supports_auth_method?(oauth_application, auth_method)
      return super unless auth_method == "none"

      request.params.key?("code_verifier") || super
    end

    def validate_authorize_params
      validate_pkce_challenge_params

      super
    end

    def create_oauth_grant(create_params = {})
      # PKCE flow
      if (code_challenge = param_or_nil("code_challenge"))
        code_challenge_method = param_or_nil("code_challenge_method") || oauth_pkce_challenge_method

        create_params[oauth_grants_code_challenge_column] = code_challenge
        create_params[oauth_grants_code_challenge_method_column] = code_challenge_method
      end

      super
    end

    def create_token_from_authorization_code(grant_params, *args, oauth_grant: nil)
      oauth_grant ||= valid_locked_oauth_grant(grant_params)

      if oauth_grant[oauth_grants_code_challenge_column]
        code_verifier = param_or_nil("code_verifier")

        redirect_response_error("invalid_request") unless code_verifier && check_valid_grant_challenge?(oauth_grant, code_verifier)
      elsif oauth_require_pkce
        redirect_response_error("code_challenge_required")
      end

      super({ oauth_grants_id_column => oauth_grant[oauth_grants_id_column] }, *args, oauth_grant: oauth_grant)
    end

    def validate_pkce_challenge_params
      if param_or_nil("code_challenge")

        challenge_method = param_or_nil("code_challenge_method")

        # Reject the weak "plain" transform unless it has been explicitly opted into. This runs
        # before the supported-method check so the disabled method surfaces a meaningful error
        # instead of the generic "code challenge required".
        redirect_response_error("unsupported_transform_algorithm") if challenge_method == "plain" && !oauth_pkce_allow_plain_method

        redirect_response_error("code_challenge_required") unless oauth_pkce_challenge_methods.include?(challenge_method)
      else
        return unless oauth_require_pkce

        redirect_response_error("code_challenge_required")
      end
    end

    def check_valid_grant_challenge?(grant, verifier)
      challenge = grant[oauth_grants_code_challenge_column]

      case grant[oauth_grants_code_challenge_method_column]
      when "plain"
        # A grant stored with the weak "plain" method must not be redeemable unless the
        # method has been explicitly enabled, otherwise PKCE is silently downgraded.
        redirect_response_error("unsupported_transform_algorithm") unless oauth_pkce_allow_plain_method
        timing_safe_eql?(verifier.to_s, challenge.to_s)
      when "S256"
        generated_challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false)

        timing_safe_eql?(generated_challenge, challenge.to_s)
      else
        redirect_response_error("unsupported_transform_algorithm")
      end
    end

    # The PKCE transform methods the server accepts. "S256" is always supported; the weak "plain"
    # transform is only included when explicitly opted into via oauth_pkce_allow_plain_method.
    def oauth_pkce_challenge_methods
      oauth_pkce_allow_plain_method ? %w[S256 plain] : %w[S256]
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        # RFC 8414: code_challenge_methods_supported is a JSON array of the supported methods.
        data[:code_challenge_methods_supported] = oauth_pkce_challenge_methods
      end
    end
  end
end
