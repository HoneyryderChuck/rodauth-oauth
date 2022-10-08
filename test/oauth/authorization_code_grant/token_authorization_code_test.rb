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
    oauth_grant = set_oauth_grant(oauth_application: oauth_app)
    post("/token",
         client_id: oauth_app[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
  end

  def test_token_authorization_code_some_other_application
    setup_application

    other_application = set_oauth_application(client_id: "OTHER_ID")

    post("/token",
         client_id: other_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    assert last_response.status == 400
    assert json_body["error"] == "invalid_grant"
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

    assert db[:oauth_grants].count == 1

    oauth_grant = db[:oauth_grants].first

    verify_access_token_response(json_body, oauth_grant)
  end

  def test_token_authorization_code_client_secret_basic
    setup_application
    oauth_app = oauth_application(token_endpoint_auth_method: "client_secret_basic")
    oauth_grant = set_oauth_grant(oauth_application: oauth_app)
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
    oauth_grant = set_oauth_grant(oauth_application: oauth_app)

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
    oauth_grant = set_oauth_grant(oauth_application: oauth_app)

    post("/token",
         client_id: oauth_app[:client_id],
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])
    assert last_response.status == 200
  end

  def test_token_authorization_code_reuse_token
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

    assert db[:oauth_grants].count == 1
    oauth_grant = db[:oauth_grants].first
    verify_access_token_response(json_body, oauth_grant)

    # second go at it
    login
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=#{CGI.escape(oauth_application[:scopes])}"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"

    check "user.read"
    check "user.write"
    # submit authorization request
    click_button "Authorize"
    assert page.current_url.start_with?("#{oauth_application[:redirect_uri]}?code="),
           "was redirected instead to #{page.current_url}"

    grant_code = page.current_url[/code=(.+)/, 1]

    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: grant_code,
         redirect_uri: oauth_grant[:redirect_uri])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_grants].count == 1
    oauth_grant2 = db[:oauth_grants].first
    verify_access_token_response(json_body, oauth_grant2)

    assert oauth_grant[:id] == oauth_grant2[:id]
    assert oauth_grant[:token] == oauth_grant2[:token]
  end

  def test_token_authorization_code_hash_columns_successful
    rodauth do
      oauth_grants_token_hash_column :token_hash
      oauth_grants_refresh_token_hash_column :refresh_token_hash
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

    assert db[:oauth_grants].count == 1

    oauth_grant = db[:oauth_grants].first

    assert oauth_grant[:token].nil?
    assert !oauth_grant[:token_hash].nil?
    assert oauth_grant[:refresh_token].nil?
    assert !oauth_grant[:refresh_token_hash].nil?

    assert json_body["access_token"] != oauth_grant[:token_hash]
    assert json_body["refresh_token"] != oauth_grant[:refresh_token_hash]
    assert !json_body["expires_in"].nil?

    header "Accept", "application/json"
    header "Authorization", "Bearer #{json_body['access_token']}"
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  def test_token_authorization_code_hash_columns_reuse_token
    rodauth do
      oauth_reuse_access_token true
      oauth_grants_token_hash_column :token_hash
      oauth_grants_refresh_token_hash_column :refresh_token_hash
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

    assert db[:oauth_grants].count == 1
    oauth_grant = db[:oauth_grants].first
    assert oauth_grant[:token].nil?
    assert !oauth_grant[:token_hash].nil?
    assert oauth_grant[:refresh_token].nil?
    assert !oauth_grant[:refresh_token_hash].nil?

    assert json_body["access_token"] != oauth_grant[:token_hash]
    assert json_body["refresh_token"] != oauth_grant[:refresh_token_hash]
    assert !json_body["expires_in"].nil?

    # second go at it
    login
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=#{CGI.escape(oauth_application[:scopes])}"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"

    check "user.read"
    check "user.write"
    # submit authorization request
    click_button "Authorize"
    assert page.current_url.start_with?("#{oauth_application[:redirect_uri]}?code="),
           "was redirected instead to #{page.current_url}"

    grant_code = page.current_url[/code=(.+)/, 1]

    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: grant_code,
         redirect_uri: oauth_grant[:redirect_uri])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_grants].count == 1
    oauth_grant2 = db[:oauth_grants].first

    assert oauth_grant[:id] == oauth_grant2[:id]
    assert oauth_grant[:token] == oauth_grant2[:token]
  end

  def test_token_authorization_code_online_successful
    rodauth do
      use_oauth_access_type? true
    end
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

    assert db[:oauth_grants].count == 1

    oauth_grant = db[:oauth_grants].first

    assert json_body["access_token"] == oauth_grant[:token]
    assert json_body["refresh_token"].nil?
    assert !json_body["expires_in"].nil?
  end

  private

  def setup_application
    super
    header "Accept", "application/json"
  end

  def oauth_feature
    :oauth_authorization_code_grant
  end
end
