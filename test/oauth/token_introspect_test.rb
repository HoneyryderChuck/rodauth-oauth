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

    grant = oauth_grant_with_token(expires_in: Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, seconds: 20))

    # valid token, and now we're getting somewhere
    post("/introspect", {
           token: grant[:token]
         })
    assert last_response.status == 200
    assert json_body == { "active" => false }
  end

  def test_oauth_introspect_unknown_token_hint
    setup_application
    login

    header "Accept", "application/json"

    # valid token, and now we're getting somewhere
    post("/introspect", {
           token: oauth_grant_with_token[:refresh_token],
           token_type_hint: "wups"
         })
    assert last_response.status == 400
    assert json_body["error"] == "unsupported_token_type"
  end

  def test_oauth_introspect_access_token
    setup_application
    login

    header "Accept", "application/json"

    # valid token, and now we're getting somewhere
    post("/introspect", {
           token: oauth_grant_with_token[:token]
         })
    assert last_response.status == 200
    assert json_body["active"] == true
    assert json_body["username"] == account[:email]
    assert json_body["scope"] == oauth_grant_with_token[:scopes]
    assert json_body["client_id"] == oauth_application[:client_id]
    assert json_body["token_type"] == "bearer"
    assert json_body.key?("exp")
  end

  def test_oauth_introspect_refresh_token
    setup_application
    login

    header "Accept", "application/json"

    # valid token, and now we're getting somewhere
    post("/introspect", {
           token: oauth_grant_with_token[:refresh_token]
         })
    assert last_response.status == 200
    assert json_body["active"] == true
    assert json_body["username"] == account[:email]
    assert json_body["scope"] == oauth_grant_with_token[:scopes]
    assert json_body["client_id"] == oauth_application[:client_id]
    assert json_body["token_type"] == "bearer"
    assert json_body.key?("exp")
  end

  def test_oauth_introspect_refresh_token_wrong_token_hint
    setup_application
    login

    header "Accept", "application/json"

    # valid token, and now we're getting somewhere
    post("/introspect", {
           token: oauth_grant_with_token[:refresh_token],
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
           token: oauth_grant_with_token[:refresh_token],
           token_type_hint: "refresh_token"
         })
    assert last_response.status == 200
    assert json_body["active"] == true
  end

  def test_oauth_introspect_access_token_credentials_grant
    setup_application

    header "Accept", "application/json"

    grant = set_oauth_grant_with_token(type: "client_credentials", account_id: nil)

    # valid token, and now we're getting somewhere
    post("/introspect", {
           client_id: oauth_application[:client_id],
           client_secret: "CLIENT_SECRET",
           token: grant[:token]
         })
    assert last_response.status == 200
    assert json_body["active"] == true
    assert json_body["username"] == "Foo"
    assert json_body["scope"] == grant[:scopes]
    assert json_body["client_id"] == oauth_application[:client_id]
    assert json_body["token_type"] == "bearer"
    assert json_body.key?("exp")
  end

  def test_oauth_introspect_access_token_client_credentials_auth
    setup_application
    header "Accept", "application/json"
    client_credentials_grant = set_oauth_grant_with_token(type: "client_credentials", account_id: nil, token: "CLIENT_TOKEN",
                                                          refresh_token: "CLIENT_REFRESH_TOKEN")
    header "Authorization", "Bearer #{client_credentials_grant[:token]}"

    # valid token, and now we're getting somewhere
    post("/introspect", {
           token: oauth_grant_with_token[:token]
         })
    assert last_response.status == 200
    assert json_body["active"] == true
    assert json_body["username"] == account[:email]
    assert json_body["scope"] == oauth_grant_with_token[:scopes]
    assert json_body["client_id"] == oauth_application[:client_id]
    assert json_body["token_type"] == "bearer"
    assert json_body.key?("exp")
  end

  private

  def oauth_feature
    :oauth_token_introspection
  end

  # overriding to implement the client/secret basic authorization
  def login
    header "Authorization", "Basic #{authorization_header(
      username: oauth_application[:client_id],
      password: 'CLIENT_SECRET'
    )}"
  end
end
