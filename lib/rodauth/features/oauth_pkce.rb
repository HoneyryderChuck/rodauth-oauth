# frozen_string_literal: true

require "rodauth/oauth/refinements"

module Rodauth
  Feature.define(:oauth_pkce, :OauthPkce) do
    using PrefixExtensions

    depends :oauth_base

    auth_value_method :use_oauth_pkce?, true

    auth_value_method :oauth_require_pkce, false
    auth_value_method :oauth_pkce_challenge_method, "S256"

    auth_value_method :code_challenge_required_error_code, "invalid_request"
    translatable_method :code_challenge_required_message, "code challenge required"
    auth_value_method :unsupported_transform_algorithm_error_code, "invalid_request"
    translatable_method :unsupported_transform_algorithm_message, "transform algorithm not supported"

    private

    def authorized_oauth_application?(oauth_application, client_secret)
      return true if use_oauth_pkce? && param_or_nil("code_verifier")

      super
    end

    def validate_oauth_grant_params
      validate_pkce_challenge_params if use_oauth_pkce?

      super
    end

    def create_oauth_grant(create_params = {})
      # PKCE flow
      if use_oauth_pkce? && (code_challenge = param_or_nil("code_challenge"))
        code_challenge_method = param_or_nil("code_challenge_method")

        create_params[oauth_grants_code_challenge_column] = code_challenge
        create_params[oauth_grants_code_challenge_method_column] = code_challenge_method
      end

      super
    end

    def create_oauth_token_from_authorization_code(oauth_grant, create_params)
      if use_oauth_pkce?
        if oauth_grant[oauth_grants_code_challenge_column]
          code_verifier = param_or_nil("code_verifier")

          redirect_response_error("invalid_request") unless code_verifier && check_valid_grant_challenge?(oauth_grant, code_verifier)
        elsif oauth_require_pkce
          redirect_response_error("code_challenge_required")
        end
      end

      super
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
        data[:code_challenge_methods_supported] = oauth_pkce_challenge_method if use_oauth_pkce?
      end
    end
  end
end
