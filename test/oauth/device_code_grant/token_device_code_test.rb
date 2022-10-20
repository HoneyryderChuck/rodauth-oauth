# frozen_string_literal: true

require "test_helper"

class RodauthOAuthTokenDeviceCodeTest < RodaIntegration
  include Rack::Test::Methods

  def test_token_device_code_no_params
    setup_application

    post("/token")
    assert last_response.status == 401
    assert json_body["error"] == "invalid_client"
  end

  def test_token_device_code_no_grant_type
    setup_application
    header "Authorization", "Basic #{authorization_header(
      username: oauth_application[:client_id],
      password: 'CLIENT_SECRET'
    )}"
    post("/token", device_code: "CODE")

    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
  end

  def test_token_device_code_unsupported_grant_type
    setup_application
    header "Authorization", "Basic #{authorization_header(
      username: oauth_application[:client_id],
      password: 'CLIENT_SECRET'
    )}"
    post("/token",
         grant_type: "smthsmth",
         device_code: "CODE")

    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
  end

  def test_token_device_code_grant_type_no_code
    setup_application
    header "Authorization", "Basic #{authorization_header(
      username: oauth_application[:client_id],
      password: 'CLIENT_SECRET'
    )}"
    post("/token",
         grant_type: "urn:ietf:params:oauth:grant-type:device_code")

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
    # assert json_body["error"] == "unsupported_grant_type"
  end

  def test_token_device_code_expired_grant
    setup_application(:oauth_device_code_grant)
    grant = oauth_grant(user_code: "USERCODE", expires_in: Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, seconds: 60))

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "urn:ietf:params:oauth:grant-type:device_code",
         device_code: grant[:code])

    assert last_response.status == 400
    assert json_body["error"] == "expired_token"
  end

  def test_token_device_code_revoked_grant
    setup_application(:oauth_device_code_grant)
    grant = oauth_grant(user_code: "USERCODE", revoked_at: Sequel::CURRENT_TIMESTAMP)

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "urn:ietf:params:oauth:grant-type:device_code",
         device_code: grant[:code])

    assert last_response.status == 400
    assert json_body["error"] == "access_denied"
  end

  def test_token_device_code_unverified_grant
    setup_application(:oauth_device_code_grant)
    grant = oauth_grant(user_code: "USERCODE", account_id: nil)

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "urn:ietf:params:oauth:grant-type:device_code",
         device_code: grant[:code])

    assert last_response.status == 400
    assert json_body["error"] == "authorization_pending"
  end

  def test_token_device_code_some_other_application
    setup_application(:oauth_device_code_grant)
    grant = oauth_grant(user_code: "USERCODE", account_id: nil)
    other_application = set_oauth_application(client_id: "OTHER_ID")

    post("/token",
         client_id: other_application[:client_id],
         grant_type: "urn:ietf:params:oauth:grant-type:device_code",
         device_code: grant[:code])

    assert last_response.status == 400
    assert json_body["error"] == "invalid_grant"
  end

  def test_token_device_code_unverified_grant_slow_down
    rodauth do
      oauth_device_code_grant_polling_interval 2
    end
    setup_application(:oauth_device_code_grant)
    grant = oauth_grant(user_code: "USERCODE", account_id: nil)

    post("/token", client_id: oauth_application[:client_id], grant_type: "urn:ietf:params:oauth:grant-type:device_code",
                   device_code: grant[:code])
    assert last_response.status == 400
    assert json_body["error"] == "authorization_pending"
    @json_body = nil
    post("/token", client_id: oauth_application[:client_id], grant_type: "urn:ietf:params:oauth:grant-type:device_code",
                   device_code: grant[:code])
    assert last_response.status == 400
    assert json_body["error"] == "slow_down"
    sleep 2
    @json_body = nil
    post("/token", client_id: oauth_application[:client_id], grant_type: "urn:ietf:params:oauth:grant-type:device_code",
                   device_code: grant[:code])
    assert last_response.status == 400
    assert json_body["error"] == "authorization_pending"
  end

  def test_token_device_code_denied_grant
    setup_application(:oauth_device_code_grant)
    grant = oauth_grant(user_code: "12345678", account_id: account[:id], revoked_at: Sequel::CURRENT_TIMESTAMP)

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "urn:ietf:params:oauth:grant-type:device_code",
         device_code: grant[:code])

    assert last_response.status == 400
    assert json_body["error"] == "access_denied"
  end

  def test_token_device_code_no_device_code
    setup_application(:oauth_device_code_grant)

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "urn:ietf:params:oauth:grant-type:device_code")

    assert last_response.status == 400
    assert last_response.headers["Content-Type"] == "application/json"
    assert json_body["error"] == "invalid_request"
  end

  def test_token_device_code_successful
    setup_application(:oauth_device_code_grant)
    grant = oauth_grant(code: "CODE", user_code: nil, account_id: account[:id])

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "urn:ietf:params:oauth:grant-type:device_code",
         device_code: grant[:code])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_grants].count == 1
    grant = db[:oauth_grants].first
    verify_access_token_response(json_body, grant)
  end

  def test_token_device_code_client_authenticated_successful
    setup_application(:oauth_device_code_grant)
    grant = oauth_grant(code: "CODE", user_code: nil, account_id: account[:id], revoked_at: Sequel::CURRENT_TIMESTAMP)

    header "Authorization", "Basic #{authorization_header(
      username: oauth_application[:client_id],
      password: 'CLIENT_SECRET'
    )}"

    post("/token",
         grant_type: "urn:ietf:params:oauth:grant-type:device_code",
         device_code: grant[:code])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_grants].count == 1
    grant = db[:oauth_grants].first
    verify_access_token_response(json_body, grant)
  end

  private

  def setup_application(*)
    rodauth do
      oauth_token_endpoint_auth_methods_supported %w[client_secret_basic none]
    end
    super
    header "Accept", "application/json"
  end

  def default_grant_type
    "device_code"
  end
end
