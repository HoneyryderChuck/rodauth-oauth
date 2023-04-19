# frozen_string_literal: true

require "test_helper"
require_relative "./token_authorization_code"

class RodauthOAuthTokenAuthorizationCodeFormPostTest < RodaIntegration
  include RodauthOAuthTokenAuthorizationCodeTest

  def test_token_authorization_code_no_params
    setup_application

    post("/token")
    verify_response(401)
    assert json_body["error"] == "invalid_client"
  end

  def test_token_authorization_code_no_client_secret
    setup_application

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    verify_response(401)
    assert json_body["error"] == "invalid_client"
  end

  def test_token_authorization_code_forbidden_client_secret_basic
    setup_application
    oauth_app = oauth_application(token_endpoint_auth_method: "client_secret_post")
    oauth_grant = set_oauth_grant(oauth_application: oauth_app)

    header "Authorization", "Basic #{authorization_header(
      username: oauth_app[:client_id],
      password: 'CLIENT_SECRET'
    )}"
    post("/token",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    verify_response(401)

    header "Authorization", nil
    post("/token", client_id: oauth_app[:client_id],
                   client_secret: "CLIENT_SECRET",
                   grant_type: "authorization_code",
                   code: oauth_grant[:code],
                   redirect_uri: oauth_grant[:redirect_uri])
    verify_response(200)
  end

  def test_token_authorization_code_invalid_client_id
    setup_application

    post("/token",
         client_id: "INVALID_CLIENT_ID",
         client_secret: oauth_application[:client_secret],
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    verify_response(401)
    assert json_body["error"] == "invalid_client"
  end

  private

  def post_token(request_args)
    request_args = {
      client_id: oauth_application[:client_id],
      client_secret: "CLIENT_SECRET"
    }.merge(request_args).compact

    post("/token", request_args)
  end
end
