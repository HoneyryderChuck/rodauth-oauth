# frozen_string_literal: true

require "test_helper"

class RodauthOauthDeviceGrantAuthorizeTest < RodaIntegration
  include Rack::Test::Methods

  def test_authorize_post_authorize_with_device_grant_and_client_id
    setup_application(:oauth_device_code_grant)

    header "Accept", "application/json"

    post("/device-authorization", {
           client_id: oauth_application[:client_id],
           scope: "user.read+user.write"
         })
    assert last_response.status == 200

    assert db[:oauth_grants].one?,
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
    setup_application(:oauth_device_code_grant)

    header "Accept", "application/json"
    header "Authorization", "Basic #{authorization_header(
      username: oauth_application[:client_id],
      password: 'CLIENT_SECRET'
    )}"

    post("/device-authorization",
         scope: "user.read+user.write")
    assert last_response.status == 200

    assert db[:oauth_grants].one?,
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

  def test_authorize_post_device_not_logged_in
    setup_application(:oauth_device_code_grant)
    visit "/device"
    assert page.html.include?("Please login to continue")
  end

  def test_authorize_post_device_unexisting_grant
    setup_application(:oauth_device_code_grant)
    login
    visit "/device"
    assert page.html.include?("Insert the user code from the device you'd like to authorize.")

    fill_in "User code", with: "USERCODE"
    click_button "Search"

    assert page.html.include?("No device to authorize with the given user code")
  end

  def test_authorize_post_device_revoked_grant
    setup_application(:oauth_device_code_grant)
    login

    grant = set_oauth_grant(code: "CODE", user_code: "USERCODE", revoked_at: Sequel::CURRENT_TIMESTAMP)

    visit "/device"
    assert page.html.include?("Insert the user code from the device you'd like to authorize.")

    fill_in "User code", with: grant[:user_code]
    click_button "Search"

    assert page.html.include?("No device to authorize with the given user code")
  end

  def test_authorize_post_device_expired_grant
    setup_application(:oauth_device_code_grant)
    login

    grant = set_oauth_grant(code: "CODE", user_code: "USERCODE", expires_in: Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, seconds: 60))

    visit "/device"
    assert page.html.include?("Insert the user code from the device you'd like to authorize.")

    fill_in "User code", with: grant[:user_code]
    click_button "Search"

    assert page.html.include?("No device to authorize with the given user code")
  end

  def test_authorize_post_device_no_user_code
    setup_application(:oauth_device_code_grant)
    login

    grant = set_oauth_grant(code: "CODE", user_code: "USERCODE")

    visit "/device"
    assert page.html.include?("Insert the user code from the device you'd like to authorize.")

    assert_field("User code")
    fill_in "User code", with: grant[:user_code]
    click_button "Search"
    assert page.html.include?("The device with user code #{grant[:user_code]} would like to access your data.")

    # field is hidden
    first('input[name="user_code"]', visible: false).set("")
    click_button "Verify"

    assert page.html.include?("Invalid grant")
  end

  def test_authorize_post_device_successful_grant
    setup_application(:oauth_device_code_grant)
    login

    grant = set_oauth_grant(code: "CODE", user_code: "USERCODE")

    visit "/device"
    assert page.html.include?("Insert the user code from the device you'd like to authorize.")

    assert_field("User code")
    fill_in "User code", with: grant[:user_code]
    click_button "Search"

    assert page.html.include?("The device with user code #{grant[:user_code]} would like to access your data.")

    click_button "Verify"

    assert page.html.include?("The device is verified")

    assert db[:oauth_grants].where(user_code: grant[:user_code]).none?
    assert db[:oauth_grants].one?
    updated_grant = db[:oauth_grants].first
    assert updated_grant[:id] == grant[:id]
  end

  def test_authorize_post_device_complete_successful_grant
    setup_application(:oauth_device_code_grant)
    login

    grant = set_oauth_grant(code: "CODE", user_code: "USERCODE")

    visit "/device?user_code=#{grant[:user_code]}"
    assert page.html.include?("The device with user code #{grant[:user_code]} would like to access your data.")
    click_button "Verify"

    assert page.html.include?("The device is verified")

    assert db[:oauth_grants].where(user_code: grant[:user_code]).none?
    assert db[:oauth_grants].one?
    updated_grant = db[:oauth_grants].first
    assert updated_grant[:id] == grant[:id]
  end

  private

  def default_grant_type
    "device_code"
  end
end
