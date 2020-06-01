# frozen_string_literal: true

require "test_helper"

class RodaOauthHTTPMacTokenAuthorizationCodeTest < HTTPMacIntegration
  include Rack::Test::Methods

  def test_http_mac_token_authorization_code_successful
    setup_application

    post("/oauth-token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:http_mac_oauth_tokens].count == 1

    access_token = db[:http_mac_oauth_tokens].first

    oauth_grant = db[:oauth_grants].where(id: access_token[:oauth_grant_id]).first
    assert !oauth_grant[:revoked_at].nil?, "oauth grant should be revoked"

    json_body = JSON.parse(last_response.body)

    assert json_body["token"] == access_token[:token]
    assert json_body["refresh_token"] == access_token[:refresh_token]
    assert !json_body["expires_in"].nil?
    assert json_body["token_type"] == "mac"
    assert json_body["mac_key"] == access_token[:mac_key]
    assert json_body["mac_algorithm"] == "hmac-sha-256"
  end

  private

  def setup_application
    super
    header "Accept", "application/json"
  end
end
