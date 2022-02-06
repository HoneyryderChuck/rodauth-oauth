# frozen_string_literal: true

require "test_helper"

class RodauthOAuthTokenDeviceCodeTest < RodaIntegration
  include Rack::Test::Methods

  def test_token_device_code_no_params
    rodauth do
      use_oauth_device_code_grant_type? true
    end
    setup_application

    post("/token")
    assert last_response.status == 401
    assert json_body["error"] == "invalid_client"
  end

  def test_token_device_code_no_grant_type
    rodauth do
      use_oauth_device_code_grant_type? true
    end
    setup_application
    post("/token",
         client_id: oauth_application[:client_id],
         device_code: "CODE")

    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
  end

  def test_token_device_code_unsupported_grant_type
    rodauth do
      use_oauth_device_code_grant_type? true
    end
    setup_application
    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "smthsmth",
         device_code: "CODE")

    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
  end

  def test_token_device_code_no_grant
    setup_application
    header "Authorization", "Basic #{authorization_header(
      username: oauth_application[:client_id],
      password: 'CLIENT_SECRET'
    )}"
    post("/token",
         grant_type: "urn:ietf:params:oauth:grant-type:device_code",
         device_code: "CODE")

    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
  end

  def test_token_device_code_expired_grant
    rodauth do
      use_oauth_device_code_grant_type? true
    end
    setup_application
    grant = oauth_grant(user_code: "USERCODE", expires_in: Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, seconds: 60))

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "urn:ietf:params:oauth:grant-type:device_code",
         device_code: grant[:code])

    assert last_response.status == 400
    assert json_body["error"] == "expired_token"
  end

  def test_token_device_code_revoked_grant
    rodauth do
      use_oauth_device_code_grant_type? true
    end
    setup_application
    grant = oauth_grant(user_code: "USERCODE", revoked_at: Sequel::CURRENT_TIMESTAMP)

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "urn:ietf:params:oauth:grant-type:device_code",
         device_code: grant[:code])

    assert last_response.status == 400
    assert json_body["error"] == "access_denied"
  end

  def test_token_device_code_unverified_grant
    rodauth do
      use_oauth_device_code_grant_type? true
    end
    setup_application
    grant = oauth_grant(user_code: "USERCODE", account_id: nil)

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "urn:ietf:params:oauth:grant-type:device_code",
         device_code: grant[:code])

    assert last_response.status == 400
    assert json_body["error"] == "authorization_pending"
  end

  def test_token_device_code_denied_grant
    rodauth do
      use_oauth_device_code_grant_type? true
    end
    setup_application
    grant = oauth_grant(user_code: nil, account_id: account[:id], revoked_at: Sequel::CURRENT_TIMESTAMP)

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "urn:ietf:params:oauth:grant-type:device_code",
         device_code: grant[:code])

    assert last_response.status == 400
    assert json_body["error"] == "access_denied"
  end

  def test_token_device_code_successful
    rodauth do
      use_oauth_device_code_grant_type? true
    end
    setup_application
    grant = oauth_grant(user_code: nil, account_id: account[:id], revoked_at: Sequel::CURRENT_TIMESTAMP)
    token = oauth_token(oauth_grant_id: grant[:id])

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "urn:ietf:params:oauth:grant-type:device_code",
         device_code: grant[:code])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    verify_access_token_response(json_body, token)
  end

  def test_token_device_code_client_authenticated_successful
    rodauth do
      use_oauth_device_code_grant_type? true
    end
    setup_application
    grant = oauth_grant(user_code: nil, account_id: account[:id], revoked_at: Sequel::CURRENT_TIMESTAMP)
    token = oauth_token(oauth_grant_id: grant[:id])

    header "Authorization", "Basic #{authorization_header(
      username: oauth_application[:client_id],
      password: 'CLIENT_SECRET'
    )}"

    post("/token",
         grant_type: "urn:ietf:params:oauth:grant-type:device_code",
         device_code: grant[:code])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    verify_access_token_response(json_body, token)
  end

  private

  def setup_application
    super
    header "Accept", "application/json"
  end
end
