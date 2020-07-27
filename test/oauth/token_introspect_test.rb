# frozen_string_literal: true

require "test_helper"

class RodauthOAuthTokenIntrospectTest < RodaIntegration
  include Rack::Test::Methods

  def test_oauth_introspect_missing_token
    setup_application
    login

    header "Accept", "application/json"

    post("/introspect")
    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
  end

  def test_oauth_introspect_expired_token
    setup_application
    login

    header "Accept", "application/json"

    token = oauth_token(expires_in: Time.now - 20)

    # valid token, and now we're getting somewhere
    post("/introspect", {
           token: token[:token]
         })
    assert last_response.status == 200
    assert json_body == { "active" => false }
  end

  def test_oauth_introspect_access_token
    setup_application
    login

    header "Accept", "application/json"

    # valid token, and now we're getting somewhere
    post("/introspect", {
           token: oauth_token[:token]
         })
    assert last_response.status == 200
    assert json_body["active"] == true
    assert json_body["scope"] == oauth_token[:scopes]
    assert json_body["client_id"] == oauth_application[:client_id]
    assert json_body["token_type"] == "bearer"
  end

  def test_oauth_introspect_refresh_token
    setup_application
    login

    header "Accept", "application/json"

    # valid token, and now we're getting somewhere
    post("/introspect", {
           token: oauth_token[:refresh_token]
         })
    assert last_response.status == 200
    assert json_body["active"] == true
    assert json_body["scope"] == oauth_token[:scopes]
    assert json_body["client_id"] == oauth_application[:client_id]
    assert json_body["token_type"] == "bearer"
  end

  def test_oauth_introspect_refresh_token_wrong_token_hint
    setup_application
    login

    header "Accept", "application/json"

    # valid token, and now we're getting somewhere
    post("/introspect", {
           token: oauth_token[:refresh_token],
           token_type_hint: "access_token"
         })
    assert last_response.status == 200
    assert json_body == { "active" => false }
  end

  def test_oauth_introspect_refresh_token_token_hint
    setup_application
    login

    header "Accept", "application/json"

    # valid token, and now we're getting somewhere
    post("/introspect", {
           token: oauth_token[:refresh_token],
           token_type_hint: "refresh_token"
         })
    assert last_response.status == 200
    assert json_body["active"] == true
  end

  private

  # overriding to implement the client/secret basic authorization
  def login
    header "Authorization", "Basic #{authorization_header(
      username: oauth_application[:client_id],
      password: 'CLIENT_SECRET'
    )}"
  end
end
