# frozen_string_literal: true

require "rodauth/oauth"

module Rodauth
  Feature.define(:oauth_token_revocation, :OauthTokenRevocation) do
    depends :oauth_base

    before "revoke"
    after "revoke"

    notice_flash "The oauth grant has been revoked", "revoke_oauth_grant"

    # /revoke
    auth_server_route(:revoke) do |r|
      if logged_in?
        require_account
        require_oauth_application_from_account
      else
        require_oauth_application
      end

      before_revoke_route

      r.post do
        catch_error do
          validate_revoke_params

          oauth_grant = nil
          transaction do
            before_revoke
            oauth_grant = revoke_oauth_grant
            after_revoke
          end

          if accepts_json?
            json_payload = {
              "revoked_at" => convert_timestamp(oauth_grant[oauth_grants_revoked_at_column])
            }
            if param("token_type_hint") == "refresh_token"
              json_payload["refresh_token"] = oauth_grant[oauth_grants_refresh_token_column]
            else
              json_payload["token"] = oauth_grant[oauth_grants_token_column]
            end

            json_response_success json_payload
          else
            set_notice_flash revoke_oauth_grant_notice_flash
            redirect request.referer || "/"
          end
        end

        redirect_response_error("invalid_request", request.referer || "/")
      end
    end

    def validate_revoke_params(token_hint_types = %w[access_token refresh_token].freeze)
      token_hint = param_or_nil("token_type_hint")

      if features.include?(:oauth_jwt) && oauth_jwt_access_tokens && (!token_hint || token_hint == "access_token")
        # JWT access tokens can't be revoked
        throw(:rodauth_error)
      end

      # check if valid token hint type
      redirect_response_error("unsupported_token_type") if token_hint && !token_hint_types.include?(token_hint)

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

    def revoke_oauth_grant
      token = param("token")

      if param("token_type_hint") == "refresh_token"
        oauth_grant = oauth_grant_by_refresh_token(token)
        token_column = oauth_grants_refresh_token_column
      else
        oauth_grant = oauth_grant_by_token_ds(token).where(
          oauth_grants_oauth_application_id_column => oauth_application[oauth_applications_id_column]
        ).first
        token_column = oauth_grants_token_column
      end

      redirect_response_error("invalid_request") unless oauth_grant

      redirect_response_error("invalid_request") unless grant_from_application?(oauth_grant, oauth_application)

      update_params = { oauth_grants_revoked_at_column => Sequel::CURRENT_TIMESTAMP }

      ds = db[oauth_grants_table].where(oauth_grants_id_column => oauth_grant[oauth_grants_id_column])

      oauth_grant = __update_and_return__(ds, update_params)

      oauth_grant[token_column] = token
      oauth_grant

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
