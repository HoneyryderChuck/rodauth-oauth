# frozen_string_literal: true

require "test_helper"

class RodauthOauthDeviceGrantAuthorizeTest < RodaIntegration
  include Rack::Test::Methods

  def test_authorize_post_authorize_no_device_grant
    setup_application

    header "Accept", "application/json"

    post("/device-authorization")

    assert last_response.status == 404
  end

  def test_authorize_post_authorize_with_device_grant_and_client_id
    rodauth do
      use_oauth_device_code_grant_type? true
    end
    setup_application

    header "Accept", "application/json"

    post("/device-authorization", {
           client_id: oauth_application[:client_id],
           scope: "user.read+user.write"
         })
    assert last_response.status == 200

    assert db[:oauth_grants].count == 1,
           "no grant has been created"

    device_grant = db[:oauth_grants].first
    assert device_grant[:oauth_application_id] == oauth_application[:id]

    assert json_body == {
      "device_code" => device_grant[:code],
      "user_code" => device_grant[:user_code],
      "verification_uri" => "http://example.org/device",
      "verification_uri_complete" =>
          "http://example.org/device?user_code=#{device_grant[:user_code]}",
      "expires_in" => 5 * 60,
      "interval" => 5
    }
  end

  def test_authorize_post_authorize_with_device_grant
    rodauth do
      use_oauth_device_code_grant_type? true
    end
    setup_application

    header "Accept", "application/json"
    header "Authorization", "Basic #{authorization_header(
      username: oauth_application[:client_id],
      password: 'CLIENT_SECRET'
    )}"

    post("/device-authorization",
         scope: "user.read+user.write")
    assert last_response.status == 200

    assert db[:oauth_grants].count == 1,
           "no grant has been created"

    device_grant = db[:oauth_grants].first
    assert device_grant[:oauth_application_id] == oauth_application[:id]

    assert json_body == {
      "device_code" => device_grant[:code],
      "user_code" => device_grant[:user_code],
      "verification_uri" => "http://example.org/device",
      "verification_uri_complete" =>
          "http://example.org/device?user_code=#{device_grant[:user_code]}",
      "expires_in" => 5 * 60,
      "interval" => 5
    }
  end
end
