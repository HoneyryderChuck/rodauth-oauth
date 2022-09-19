# frozen_string_literal: true

module Rodauth
  Feature.define(:oauth_pkce, :OauthPkce) do
    depends :oauth_authorization_code_grant

    auth_value_method :oauth_require_pkce, false
    auth_value_method :oauth_pkce_challenge_method, "S256"

    auth_value_method :oauth_grants_code_challenge_column, :code_challenge
    auth_value_method :oauth_grants_code_challenge_method_column, :code_challenge_method

    auth_value_method :oauth_code_challenge_required_error_code, "invalid_request"
    translatable_method :oauth_code_challenge_required_message, "code challenge required"
    auth_value_method :oauth_unsupported_transform_algorithm_error_code, "invalid_request"
    translatable_method :oauth_unsupported_transform_algorithm_message, "transform algorithm not supported"

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
        code_challenge_method = param_or_nil("code_challenge_method")

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
        redirect_response_error("code_challenge_required") unless oauth_pkce_challenge_method == challenge_method
      else
        return unless oauth_require_pkce

        redirect_response_error("code_challenge_required")
      end
    end

    def check_valid_grant_challenge?(grant, verifier)
      challenge = grant[oauth_grants_code_challenge_column]

      case grant[oauth_grants_code_challenge_method_column]
      when "plain"
        challenge == verifier
      when "S256"
        generated_challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(verifier))
        generated_challenge.delete_suffix!("=") while generated_challenge.end_with?("=")

        challenge == generated_challenge
      else
        redirect_response_error("unsupported_transform_algorithm")
      end
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:code_challenge_methods_supported] = oauth_pkce_challenge_method
      end
    end
  end
end
