# frozen_string_literal: true

require "test_helper"

class RodauthClientCredentialsGrantOAuthTokenAuthorizationCodeTest < RodaIntegration
  include Rack::Test::Methods

  def test_token_authorization_code_no_client_secret
    setup_application

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "client_credentials")

    assert last_response.status == 401
    assert json_body["error"] == "invalid_client"
  end

  def test_token_authorization_code_with_scope
    setup_application

    post("/token",
         client_id: oauth_application[:client_id],
         scope: "user.read user.write",
         client_secret: "CLIENT_SECRET",
         grant_type: "client_credentials")

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_grants].one?

    oauth_grant = db[:oauth_grants].first
    assert oauth_grant[:scopes] == "user.read user.write"

    verify_access_token_response(json_body, oauth_grant)
    assert !json_body.key?("refresh_token")
  end

  def test_token_authorization_code_successful
    setup_application

    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "client_credentials")

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_grants].one?

    oauth_grant = db[:oauth_grants].first
    assert oauth_grant[:scopes] == "user.read user.write"

    verify_access_token_response(json_body, oauth_grant)
    assert !json_body.key?("refresh_token")
  end

  private

  def setup_application(*)
    super
    header "Accept", "application/json"
  end

  def oauth_feature
    :oauth_client_credentials_grant
  end

  def default_grant_type
    "client_credentials"
  end
end
