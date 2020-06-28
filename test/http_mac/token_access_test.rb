# frozen_string_literal: true

require "test_helper"

class RodauthOAuthHTTPMacTokenAuthorizationCodeTest < HTTPMacIntegration
  include Rack::Test::Methods

  def test_http_mac_token_no_mac_token
    setup_application

    header "Accept", "application/json"
    header "Authorization", "Bearer TOKEN"
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
  end

  def test_http_mac_token_incomplete_mac_token
    setup_application

    header "Accept", "application/json"
    header "Authorization", "Mac id=\"wiriwiri\""
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
  end

  def test_http_mac_token_rando_mac_token
    setup_application

    header "Accept", "application/json"
    header "Authorization", "Mac id=\"wiriwiri\", nonce=\"12434:wiri\", mac_signature=\"wiri\""
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
  end

  def test_http_mac_token_access_private_valid_token
    setup_application

    header "Accept", "application/json"
    header "Authorization", set_authorization_header
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end
end
