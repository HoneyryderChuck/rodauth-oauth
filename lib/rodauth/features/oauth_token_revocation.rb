# frozen_string_literal: true

module Rodauth
  Feature.define(:oauth_token_revocation, :OauthTokenRevocation) do
    depends :oauth_base

    before "revoke"
    after "revoke"

    notice_flash "The oauth token has been revoked", "revoke_oauth_token"

    # /revoke
    route(:revoke) do |r|
      next unless is_authorization_server?

      before_revoke_route

      if logged_in?
        require_account
        require_oauth_application_from_account
      else
        require_oauth_application
      end

      r.post do
        catch_error do
          validate_oauth_revoke_params

          oauth_token = nil
          transaction do
            before_revoke
            oauth_token = revoke_oauth_token
            after_revoke
          end

          if accepts_json?
            json_response_success \
              "token" => oauth_token[oauth_tokens_token_column],
              "refresh_token" => oauth_token[oauth_tokens_refresh_token_column],
              "revoked_at" => convert_timestamp(oauth_token[oauth_tokens_revoked_at_column])
          else
            set_notice_flash revoke_oauth_token_notice_flash
            redirect request.referer || "/"
          end
        end

        redirect_response_error("invalid_request", request.referer || "/")
      end
    end

    def validate_oauth_revoke_params(token_hint_types = %w[access_token refresh_token].freeze)
      # check if valid token hint type
      if param_or_nil("token_type_hint") && !token_hint_types.include?(param("token_type_hint"))
        redirect_response_error("unsupported_token_type")
      end

      redirect_response_error("invalid_request") unless param_or_nil("token")
    end

    def check_csrf?
      case request.path
      when revoke_path
        !json_request?
      else
        super
      end
    end

    private

    def revoke_oauth_token
      token = param("token")

      oauth_token = if param("token_type_hint") == "refresh_token"
                      oauth_token_by_refresh_token(token)
                    else
                      oauth_token_by_token(token)
                    end

      redirect_response_error("invalid_request") unless oauth_token

      redirect_response_error("invalid_request") unless token_from_application?(oauth_token, oauth_application)

      update_params = { oauth_tokens_revoked_at_column => Sequel::CURRENT_TIMESTAMP }

      ds = db[oauth_tokens_table].where(oauth_tokens_id_column => oauth_token[oauth_tokens_id_column])

      oauth_token = __update_and_return__(ds, update_params)

      oauth_token[oauth_tokens_token_column] = token
      oauth_token

      # If the particular
      # token is a refresh token and the authorization server supports the
      # revocation of access tokens, then the authorization server SHOULD
      # also invalidate all access tokens based on the same authorization
      # grant
      #
      # we don't need to do anything here, as we revalidate existing tokens
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:revocation_endpoint] = revoke_url
        data[:revocation_endpoint_auth_methods_supported] = nil # because it's client_secret_basic
      end
    end
  end
end
