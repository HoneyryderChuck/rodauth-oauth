# frozen_string_literal: true

require "test_helper"

class RodaOauthTokenIntrospectTest < RodaIntegration
  include Rack::Test::Methods

  def test_oauth_introspect_unauthenticated
    setup_application

    header "Accept", "application/json"
    post("/oauth-introspect")
    assert last_response.status == 401
  end

  def test_oauth_introspect_missing_token
    setup_application

    header "Accept", "application/json"
    set_authorization_header

    post("/oauth-introspect")
    assert last_response.status == 400
  end

  def test_oauth_introspect_expired_token
    setup_application

    header "Accept", "application/json"
    set_authorization_header

    token = oauth_token(expires_in: Time.now - 20)

    # valid token, and now we're getting somewhere
    post("/oauth-introspect", {
           token: token[:token]
         })
    assert last_response.status == 200
    json_body = JSON.parse(last_response.body)
    assert json_body == { active: false }
  end

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
  end

  def test_oauth_introspect_refresh_token
    setup_application

    header "Accept", "application/json"
    set_authorization_header

    # valid token, and now we're getting somewhere
    post("/oauth-introspect", {
           token: oauth_token[:refresh_token]
         })
    assert last_response.status == 200
    json_body = JSON.parse(last_response.body)
    assert json_body["active"] == true
    assert json_body["scopes"] == oauth_token[:scopes].gsub(",", " ")
    assert json_body["client_id"] == oauth_application[:client_id]
    assert json_body["token_type"] == bearer
  end

  def test_oauth_introspect_refresh_token_wrong_token_hint
    setup_application

    header "Accept", "application/json"
    set_authorization_header

    # valid token, and now we're getting somewhere
    post("/oauth-introspect", {
           token: oauth_token[:refresh_token],
           token_type_hint: "access_token"
         })
    assert last_response.status == 200
    json_body = JSON.parse(last_response.body)
    assert json_body == { active: false }

    # valid token, and now we're getting somewhere
    post("/oauth-introspect", {
           token: oauth_token[:refresh_token],
           token_type_hint: "refresh_token"
         })
    assert last_response.status == 200
    json_body = JSON.parse(last_response.body)
    assert json_body["active"] == true
  end

  private

  # overriding to implement the client/secret basic authorization
  def set_authorization_header
    header "Authorization", "Basic #{Base64.strict_encode64('CLIENT_ID:CLIENT_SECRET')}"
  end
end
