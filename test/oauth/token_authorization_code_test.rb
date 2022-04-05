# frozen_string_literal: true

require "test_helper"

class RodauthOAuthTokenAuthorizationCodeTest < RodaIntegration
  include Rack::Test::Methods

  def test_token_authorization_code_no_params
    setup_application

    post("/token")
    assert last_response.status == 401
    assert json_body["error"] == "invalid_client"
  end

  def test_token_authorization_code_no_grant_type
    setup_application
    post("/token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         code: "CODE")

    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
  end

  def test_token_authorization_code_unsupported_grant_type
    setup_application
    post("/token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "smthsmth",
         code: "CODE")

    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
  end

  def test_token_authorization_code_no_grant
    setup_application
    post("/token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: "CODE")

    assert last_response.status == 400
    assert json_body["error"] == "invalid_grant"
  end

  def test_token_authorization_code_expired_grant
    setup_application
    grant = oauth_grant(expires_in: Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, seconds: 60))

    post("/token",
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
    grant = oauth_grant(revoked_at: Sequel::CURRENT_TIMESTAMP)

    post("/token",
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

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    assert last_response.status == 401
    assert json_body["error"] == "invalid_client"
  end

  def test_token_authorization_code_unsupported_application_grant_type
    setup_application
    oauth_app = oauth_application(grant_types: "implicit")
    oauth_grant = set_oauth_grant(oauth_app)
    post("/token",
         client_id: oauth_app[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
  end

  def test_token_authorization_code_successful
    setup_application

    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_tokens].count == 1

    oauth_token = db[:oauth_tokens].first

    verify_oauth_grant_revoked(oauth_token)
    verify_access_token_response(json_body, oauth_token)
  end

  def test_token_authorization_code_client_secret_basic
    setup_application
    oauth_app = oauth_application(token_endpoint_auth_method: "client_secret_basic")
    oauth_grant = set_oauth_grant(oauth_app)
    post("/token",
         client_id: oauth_app[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])
    assert last_response.status == 401

    header "Authorization", "Basic #{authorization_header(
      username: oauth_app[:client_id],
      password: 'CLIENT_SECRET'
    )}"
    post("/token",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    assert last_response.status == 200
  end

  def test_token_authorization_code_client_secret_post
    setup_application
    oauth_app = oauth_application(token_endpoint_auth_method: "client_secret_post")
    oauth_grant = set_oauth_grant(oauth_app)

    header "Authorization", "Basic #{authorization_header(
      username: oauth_app[:client_id],
      password: 'CLIENT_SECRET'
    )}"
    post("/token",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    assert last_response.status == 401

    header "Authorization", nil
    post("/token",
         client_id: oauth_app[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])
    assert last_response.status == 200
  end

  def test_token_authorization_code_none
    setup_application
    oauth_app = oauth_application(token_endpoint_auth_method: "none")
    oauth_grant = set_oauth_grant(oauth_app)

    post("/token",
         client_id: oauth_app[:client_id],
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])
    assert last_response.status == 200
  end

  def test_token_authorization_code_reuse_token_successful
    rodauth do
      oauth_reuse_access_token true
    end
    setup_application

    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_tokens].count == 1
    oauth_token = db[:oauth_tokens].first
    verify_oauth_grant_revoked(oauth_token)
    verify_access_token_response(json_body, oauth_token)

    # second go at it
    @oauth_grant = nil
    another_grant = oauth_grant(code: "CODE2")

    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: another_grant[:code],
         redirect_uri: another_grant[:redirect_uri])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_tokens].count == 1
    oauth_token2 = db[:oauth_tokens].first
    verify_oauth_grant_revoked(oauth_token2)
    verify_access_token_response(json_body, oauth_token2)

    assert oauth_token[:id] == oauth_token2[:id]
    assert oauth_token[:token] == oauth_token2[:token]
  end

  def test_token_authorization_code_hash_columns_successful
    rodauth do
      oauth_tokens_token_hash_column :token_hash
      oauth_tokens_refresh_token_hash_column :refresh_token_hash
    end
    setup_application

    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_tokens].count == 1

    access_token = db[:oauth_tokens].first

    verify_oauth_grant_revoked(access_token)

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

    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: online_grant[:code],
         redirect_uri: online_grant[:redirect_uri])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_tokens].count == 1

    access_token = db[:oauth_tokens].first

    verify_oauth_grant_revoked(access_token)
    assert json_body["access_token"] == access_token[:token]
    assert json_body["refresh_token"].nil?
    assert !json_body["expires_in"].nil?
  end

  def test_token_authorization_code_pkce_no_code_verifier
    setup_application

    pkce_grant = oauth_grant(access_type: "online", code_challenge_method: "S256", code_challenge: PKCE_CHALLENGE)

    post("/token",
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

    post("/token",
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

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: pkce_grant[:code],
         redirect_uri: pkce_grant[:redirect_uri],
         code_verifier: PKCE_VERIFIER)

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_tokens].count == 1

    access_token = db[:oauth_tokens].first

    verify_oauth_grant_revoked(access_token)

    assert json_body["access_token"] == access_token[:token]
    assert json_body["refresh_token"].nil?
    assert !json_body["expires_in"].nil?
  end

  def test_token_authorization_code_pkce_with_plain_code_verifier
    setup_application

    pkce_grant = oauth_grant(access_type: "online", code_challenge_method: "plain", code_challenge: PKCE_VERIFIER)

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: pkce_grant[:code],
         redirect_uri: pkce_grant[:redirect_uri],
         code_verifier: PKCE_VERIFIER)

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_tokens].count == 1

    access_token = db[:oauth_tokens].first

    verify_oauth_grant_revoked(access_token)
    assert json_body["access_token"] == access_token[:token]
    assert json_body["refresh_token"].nil?
    assert !json_body["expires_in"].nil?
  end

  def test_token_authorization_code_required_pkce_no_code_verifier
    rodauth do
      oauth_require_pkce true
    end
    setup_application

    post("/token",
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
