# frozen_string_literal: true

require "test_helper"
require_relative "./token_authorization_code"

class RodauthOAuthTokenAuthorizationCodeNoneTest < RodaIntegration
  include RodauthOAuthTokenAuthorizationCodeTest

  def test_token_authorization_code_no_params
    setup_application

    post("/token")
    verify_response(401)
    assert json_body["error"] == "invalid_client"
  end

  private

  def set_oauth_application(params = {})
    super({ token_endpoint_auth_method: "none" }.merge(params))
  end

  def post_token(request_args)
    request_args = {
      client_id: request_args.delete(:client_id) || oauth_application[:client_id]
    }.merge(request_args).compact

    post("/token", request_args)
  end
end
