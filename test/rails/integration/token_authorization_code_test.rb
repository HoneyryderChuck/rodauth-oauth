# frozen_string_literal: true

require "test_helper"

class RodauthOAuthRailsTokenAuthorizationCodeTest < RailsIntegrationTest
  include Rack::Test::Methods

  def test_token_rails_authorization_code_no_params
    setup_application

    header "Accept", "application/json"
    post("/oauth-token")

    assert last_response.status == 401
    assert json_body["error"] == "invalid_client"
  end

  def test_token_rails_authorization_code_no_grant
    setup_application
    header "Accept", "application/json"
    post("/oauth-token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: "CODE")

    assert last_response.status == 400
    assert json_body["error"] == "invalid_grant"
  end

  def test_token_rails_authorization_code_expired_grant
    setup_application
    grant = oauth_grant(expires_in: Time.now - 60)

    header "Accept", "application/json"
    post("/oauth-token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: grant[:code],
         redirect_uri: grant[:redirect_uri])

    assert last_response.status == 400
    assert json_body["error"] == "invalid_grant"
  end

  def test_token_rails_authorization_code_revoked_grant
    setup_application
    grant = oauth_grant(revoked_at: Time.now)

    header "Accept", "application/json"
    post("/oauth-token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: grant[:code],
         redirect_uri: grant[:redirect_uri])

    assert last_response.status == 400
    assert json_body["error"] == "invalid_grant"
  end

  def test_token_authorization_code_no_client_secret
    setup_application

    header "Accept", "application/json"
    post("/oauth-token",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    assert last_response.status == 401
    assert json_body["error"] == "invalid_client"
  end

  def test_token_rails_authorization_code_successful
    setup_application

    header "Accept", "application/json"
    post("/oauth-token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_tokens].count == 1

    access_token = db[:oauth_tokens].first

    oauth_grant = db[:oauth_grants].where(id: access_token[:oauth_grant_id]).first
    assert !oauth_grant[:revoked_at].nil?, "oauth grant should be revoked"

    assert json_body["access_token"] == access_token[:token]
    assert json_body["refresh_token"] == access_token[:refresh_token]
    assert !json_body["expires_in"].nil?
  end

  # Access
  def test_token_rails_access_private_unauthenticated
    setup_application
    login

    header "Accept", "application/json"
    get("/private")
    assert last_response.status == 401
  end

  def test_token_rails_access_private_revoked_token
    setup_application
    login

    header "Accept", "application/json"
    header "Authorization", "Bearer #{oauth_token(revoked_at: Time.now)[:token]}"
    # valid token, and now we're getting somewhere
    get("/private")
  end

  def test_token_rails_access_private_expired_token
    setup_application
    login

    header "Accept", "application/json"
    header "Authorization", "Bearer #{oauth_token(expires_in: Time.now - 20)[:token]}"
    # valid token, and now we're getting somewhere
    get("/private")
  end

  def test_token_rails_access_private_invalid_scope
    setup_application
    login

    header "Accept", "application/json"
    header "Authorization", "Bearer #{oauth_token(scopes: 'smthelse')[:token]}"
    # valid token, and now we're getting somewhere
    get("/private")
  end

  def test_token_rails_access_private_valid_token
    setup_application
    login

    header "Accept", "application/json"
    header "Authorization", "Bearer #{oauth_token[:token]}"
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  private

  def login
    header "Authorization", "Basic #{authorization_header}"
  end
end
