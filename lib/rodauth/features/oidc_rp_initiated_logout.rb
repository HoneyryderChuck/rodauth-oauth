# frozen_string_literal: true

require "rodauth/oauth"

module Rodauth
  Feature.define(:oidc_rp_initiated_logout, :OidcRpInitiatedLogout) do
    depends :oidc

    auth_value_method :oauth_applications_post_logout_redirect_uris_column, :post_logout_redirect_uris
    translatable_method :oauth_invalid_post_logout_redirect_uri_message, "Invalid post logout redirect URI"

    # /oidc-logout
    auth_server_route(:oidc_logout) do |r|
      require_authorizable_account
      before_oidc_logout_route

      # OpenID Providers MUST support the use of the HTTP GET and POST methods
      r.on method: %i[get post] do
        catch_error do
          validate_oidc_logout_params

          claims = oauth_application = nil

          if (id_token_hint = param_or_nil("id_token_hint"))
            #
            # why this is done:
            #
            # we need to decode the id token in order to get the application, because, if the
            # signing key is application-specific, we don't know how to verify the signature
            # beforehand. Hence, we have to do it twice: decode-and-do-not-verify, initialize
            # the @oauth_application, and then decode-and-verify.
            #
            claims = jwt_decode(id_token_hint, verify_claims: false)

            redirect_logout_with_error(oauth_invalid_client_message) unless claims

            oauth_application = db[oauth_applications_table].where(oauth_applications_client_id_column => claims["aud"]).first
            oauth_grant = db[oauth_grants_table]
                          .where(resource_owner_params)
                          .where(oauth_grants_oauth_application_id_column => oauth_application[oauth_applications_id_column])
                          .first

            unique_account_id = if oauth_grant
                                  oauth_grant[oauth_grants_account_id_column]
                                else
                                  account_id
                                end

            # check whether ID token belongs to currently logged-in user
            redirect_logout_with_error(oauth_invalid_client_message) unless claims["sub"] == jwt_subject(unique_account_id,
                                                                                                         oauth_application)

            # When an id_token_hint parameter is present, the OP MUST validate that it was the issuer of the ID Token.
            redirect_logout_with_error(oauth_invalid_client_message) unless claims && claims["iss"] == oauth_jwt_issuer
          end

          # now let's logout from IdP
          transaction do
            before_logout
            logout
            after_logout
          end

          error_message = logout_notice_flash

          if (post_logout_redirect_uri = param_or_nil("post_logout_redirect_uri"))
            error_message = catch(:default_logout_redirect) do
              throw(:default_logout_redirect, oauth_invalid_client_message) unless claims

              oauth_application = db[oauth_applications_table].where(oauth_applications_client_id_column => claims["client_id"]).first

              throw(:default_logout_redirect, oauth_invalid_client_message) unless oauth_application

              post_logout_redirect_uris = oauth_application[oauth_applications_post_logout_redirect_uris_column].split(" ")

              unless post_logout_redirect_uris.include?(post_logout_redirect_uri)
                throw(:default_logout_redirect,
                      oauth_invalid_post_logout_redirect_uri_message)
              end

              if (state = param_or_nil("state"))
                post_logout_redirect_uri = URI(post_logout_redirect_uri)
                params = ["state=#{CGI.escape(state)}"]
                params << post_logout_redirect_uri.query if post_logout_redirect_uri.query
                post_logout_redirect_uri.query = params.join("&")
                post_logout_redirect_uri = post_logout_redirect_uri.to_s
              end

              redirect(post_logout_redirect_uri)
            end

          end

          redirect_logout_with_error(error_message)
        end

        redirect_response_error("invalid_request")
      end
    end

    private

    # Logout

    def validate_oidc_logout_params
      # check if valid token hint type
      return unless (redirect_uri = param_or_nil("post_logout_redirect_uri"))

      return if check_valid_no_fragment_uri?(redirect_uri)

      redirect_logout_with_error(oauth_invalid_client_message)
    end

    def redirect_logout_with_error(error_message = oauth_invalid_client_message)
      set_notice_flash(error_message)
      redirect(logout_redirect)
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:end_session_endpoint] = oidc_logout_url
      end
    end
  end
end
