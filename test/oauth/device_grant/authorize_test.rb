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

  def test_authorize_post_device_not_device_grant_supported
    setup_application
    visit "/device"
    assert page.status_code == 404
  end

  def test_authorize_post_device_not_logged_in
    rodauth do
      use_oauth_device_code_grant_type? true
    end
    setup_application
    visit "/device"
    assert page.html.include?("Please login to continue")
  end

  def test_authorize_post_device_unexisting_grant
    rodauth do
      use_oauth_device_code_grant_type? true
    end
    setup_application
    login
    visit "/device"
    assert page.html.include?("Insert the user code from the device you'd like to authorize.")

    fill_in "User code", with: "USERCODE"
    click_button "Search"

    assert page.html.include?("No device to authorize with the given user code")
  end

  def test_authorize_post_device_revoked_grant
    rodauth do
      use_oauth_device_code_grant_type? true
    end
    setup_application
    login

    grant = oauth_grant(code: "CODE", user_code: "USERCODE", revoked_at: Sequel::CURRENT_TIMESTAMP)

    visit "/device"
    assert page.html.include?("Insert the user code from the device you'd like to authorize.")

    fill_in "User code", with: grant[:user_code]
    click_button "Search"

    assert page.html.include?("No device to authorize with the given user code")
  end

  def test_authorize_post_device_expired_grant
    rodauth do
      use_oauth_device_code_grant_type? true
    end
    setup_application
    login

    grant = oauth_grant(code: "CODE", user_code: "USERCODE", expires_in: Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, seconds: 60))

    visit "/device"
    assert page.html.include?("Insert the user code from the device you'd like to authorize.")

    fill_in "User code", with: grant[:user_code]
    click_button "Search"

    assert page.html.include?("No device to authorize with the given user code")
  end

  def test_authorize_post_device_successful_grant
    rodauth do
      use_oauth_device_code_grant_type? true
    end
    setup_application
    login

    grant = oauth_grant(code: "CODE", user_code: "USERCODE")

    visit "/device"
    assert page.html.include?("Insert the user code from the device you'd like to authorize.")

    assert_field("User code")
    fill_in "User code", with: grant[:user_code]
    click_button "Search"

    assert page.html.include?("The device with user code #{grant[:user_code]} would like to access your data.")

    click_button "Verify"

    assert page.html.include?("The device is verified")

    assert db[:oauth_grants].where(user_code: grant[:user_code]).none?
    assert db[:oauth_tokens].count == 1
    access_token = db[:oauth_tokens].first
    assert access_token[:oauth_grant_id] == grant[:id]
    verify_oauth_grant_revoked(access_token)
  end

  def test_authorize_post_device_complete_successful_grant
    rodauth do
      use_oauth_device_code_grant_type? true
    end
    setup_application
    login

    grant = oauth_grant(code: "CODE", user_code: "USERCODE")

    visit "/device?user_code=#{grant[:user_code]}"
    assert page.html.include?("The device with user code #{grant[:user_code]} would like to access your data.")
    click_button "Verify"

    assert page.html.include?("The device is verified")

    assert db[:oauth_grants].where(user_code: grant[:user_code]).none?
    assert db[:oauth_tokens].count == 1
    access_token = db[:oauth_tokens].first
    assert access_token[:oauth_grant_id] == grant[:id]
    verify_oauth_grant_revoked(access_token)
  end
end
