# frozen_string_literal: true

require "test_helper"
require_relative "./token_authorization_code"

class RodauthOAuthTokenAuthorizationCodeClientSecretBasicTest < RodaIntegration
  include RodauthOAuthTokenAuthorizationCodeTest

  def test_token_authorization_code_client_secret_post
    setup_application
    oauth_app = oauth_application(token_endpoint_auth_method: "client_secret_basic")
    oauth_grant = set_oauth_grant(oauth_application: oauth_app)

    post("/token",
         client_id: oauth_app[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    verify_response(401)

    header "Authorization", "Basic #{authorization_header(
      username: oauth_app[:client_id],
      password: 'CLIENT_SECRET'
    )}"
    post("/token", grant_type: "authorization_code",
                   code: oauth_grant[:code],
                   redirect_uri: oauth_grant[:redirect_uri])
    verify_response(200)
  end

  private

  def post_token(request_args)
    header "Authorization", "Basic #{authorization_header(
      username: request_args.delete(:client_id) || oauth_application[:client_id],
      password: 'CLIENT_SECRET'
    )}"

    post("/token", request_args)
  end
end
