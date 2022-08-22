# frozen_string_literal: true

require "test_helper"

class RodauthClientCredentialsGrantOAuthTokenAuthorizationCodeTest < RodaIntegration
  include Rack::Test::Methods

  def test_token_authorization_code_unsupported_grant
    setup_application
    post("/token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "client_credentials")

    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
  end

  def test_token_authorization_code_no_client_secret
    rodauth do
      use_oauth_client_credentials_grant_type? true
    end
    setup_application

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "client_credentials")

    assert last_response.status == 401
    assert json_body["error"] == "invalid_client"
  end

  def test_token_authorization_code_successful
    rodauth do
      use_oauth_client_credentials_grant_type? true
    end
    setup_application

    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "client_credentials")

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_tokens].count == 1

    oauth_token = db[:oauth_tokens].first

    verify_access_token_response(json_body, oauth_token)
    assert !json_body.key?("refresh_token")
  end

  private

  def setup_application
    super
    header "Accept", "application/json"
  end

  def oauth_feature
    :oauth_client_credentials_grant
  end
end
