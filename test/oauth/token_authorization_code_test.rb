# frozen_string_literal: true

require "test_helper"

class RodaOauthTokenAuthorizationCodeTest < RodaIntegration
  include Rack::Test::Methods

  def test_token_authorization_code_no_params
    setup_application

    post("/oauth-token")
    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
  end

  def test_token_authorization_code_no_grant
    setup_application
    post("/oauth-token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: "CODE")

    assert last_response.status == 400
    assert json_body["error"] == "invalid_grant"
  end

  def test_token_authorization_code_expired_grant
    setup_application
    grant = oauth_grant(expires_in: Time.now - 60)

    post("/oauth-token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: grant[:code],
         redirect_uri: grant[:redirect_uri])

    assert last_response.status == 400
    assert json_body["error"] == "invalid_grant"
  end

  def test_token_authorization_code_revoked_grant
    setup_application
    grant = oauth_grant(revoked_at: Time.now)

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

    post("/oauth-token",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
  end

  def test_token_authorization_code_successful
    setup_application

    post("/oauth-token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_tokens].count == 1

    access_token = db[:oauth_tokens].first

    oauth_grant = db[:oauth_grants].where(id: access_token[:oauth_grant_id]).first
    assert !oauth_grant[:revoked_at].nil?, "oauth grant should be revoked"

    assert json_body["token_type"] == "bearer"
    assert json_body["access_token"] == access_token[:token]

    assert json_body["refresh_token"] == access_token[:refresh_token]
    assert !json_body["expires_in"].nil?
  end

  def test_token_authorization_code_hash_columns_successful
    rodauth do
      oauth_tokens_token_hash_column :token_hash
      oauth_tokens_refresh_token_hash_column :refresh_token_hash
    end
    setup_application

    post("/oauth-token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_tokens].count == 1

    access_token = db[:oauth_tokens].first

    oauth_grant = db[:oauth_grants].where(id: access_token[:oauth_grant_id]).first
    assert !oauth_grant[:revoked_at].nil?, "oauth grant should be revoked"

    assert access_token[:token].nil?
    assert !access_token[:token_hash].nil?
    assert access_token[:refresh_token].nil?
    assert !access_token[:refresh_token_hash].nil?

    assert json_body["access_token"] != access_token[:token_hash]
    assert json_body["refresh_token"] != access_token[:refresh_token_hash]
    assert !json_body["expires_in"].nil?

    header "Accept", "application/json"
    header "Authorization", "Bearer #{json_body['access_token']}"
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  def test_token_authorization_code_online_successful
    setup_application

    online_grant = oauth_grant(access_type: "online")

    post("/oauth-token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: online_grant[:code],
         redirect_uri: online_grant[:redirect_uri])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_tokens].count == 1

    access_token = db[:oauth_tokens].first

    oauth_grant = db[:oauth_grants].where(id: access_token[:oauth_grant_id]).first
    assert !oauth_grant[:revoked_at].nil?, "oauth grant should be revoked"

    assert json_body["access_token"] == access_token[:token]
    assert json_body["refresh_token"].nil?
    assert !json_body["expires_in"].nil?
  end

  def test_token_authorization_code_pkce_no_code_verifier
    setup_application

    pkce_grant = oauth_grant(access_type: "online", code_challenge_method: "S256", code_challenge: PKCE_CHALLENGE)

    post("/oauth-token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: pkce_grant[:code],
         redirect_uri: pkce_grant[:redirect_uri])

    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
  end

  def test_token_authorization_code_pkce_wrong_code_verifier
    setup_application

    pkce_grant = oauth_grant(access_type: "online", code_challenge_method: "S256", code_challenge: PKCE_CHALLENGE)

    post("/oauth-token",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: pkce_grant[:code],
         redirect_uri: pkce_grant[:redirect_uri],
         code_verifier: "FAULTY_VERIFIER")

    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
  end

  def test_token_authorization_code_pkce_with_code_verifier
    setup_application

    pkce_grant = oauth_grant(access_type: "online", code_challenge_method: "S256", code_challenge: PKCE_CHALLENGE)

    post("/oauth-token",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: pkce_grant[:code],
         redirect_uri: pkce_grant[:redirect_uri],
         code_verifier: PKCE_VERIFIER)

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_tokens].count == 1

    access_token = db[:oauth_tokens].first

    oauth_grant = db[:oauth_grants].where(id: access_token[:oauth_grant_id]).first
    assert !oauth_grant[:revoked_at].nil?, "oauth grant should be revoked"

    assert json_body["access_token"] == access_token[:token]
    assert json_body["refresh_token"].nil?
    assert !json_body["expires_in"].nil?
  end

  def test_token_authorization_code_pkce_with_plain_code_verifier
    setup_application

    pkce_grant = oauth_grant(access_type: "online", code_challenge_method: "plain", code_challenge: PKCE_VERIFIER)

    post("/oauth-token",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: pkce_grant[:code],
         redirect_uri: pkce_grant[:redirect_uri],
         code_verifier: PKCE_VERIFIER)

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_tokens].count == 1

    access_token = db[:oauth_tokens].first

    oauth_grant = db[:oauth_grants].where(id: access_token[:oauth_grant_id]).first
    assert !oauth_grant[:revoked_at].nil?, "oauth grant should be revoked"

    assert json_body["access_token"] == access_token[:token]
    assert json_body["refresh_token"].nil?
    assert !json_body["expires_in"].nil?
  end

  def test_token_authorization_code_required_pkce_no_code_verifier
    rodauth do
      oauth_require_pkce true
    end
    setup_application

    post("/oauth-token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
    assert json_body["error_description"] == "code challenge required"
  end

  private

  def setup_application
    super
    header "Accept", "application/json"
  end
end
