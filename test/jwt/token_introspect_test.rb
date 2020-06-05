# frozen_string_literal: true

require "test_helper"

class RodaOauthJwtTokenIntrospectTest < RodaIntegration
  include Rack::Test::Methods

  def test_oauth_introspect_access_token
    setup_application

    header "Accept", "application/json"
    set_authorization_header

    # valid token, and now we're getting somewhere
    post("/oauth-introspect", {
           token: oauth_token[:token]
         })
    assert last_response.status == 200
    json_body = JSON.parse(last_response.body)
    assert json_body["active"] == true
    assert json_body["scopes"] == oauth_token[:scopes].gsub(",", " ")
    assert json_body["client_id"] == oauth_application[:client_id]
    assert json_body["token_type"] == bearer

    # test all other jwt props
  end
end
