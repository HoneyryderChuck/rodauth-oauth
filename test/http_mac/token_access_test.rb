# frozen_string_literal: true

require "test_helper"

class RodaOauthHTTPMacTokenAuthorizationCodeTest < HTTPMacIntegration
  include Rack::Test::Methods

  def test_token_access_private_revoked_token
    setup_application

    header "Accept", "application/json"
    header "Authorization", set_authorization_header(oauth_token(revoked_at: Time.now))
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_expired_token
    setup_application

    header "Accept", "application/json"
    header "Authorization", set_authorization_header(oauth_token(expires_in: Time.now - 20))
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_invalid_scope
    setup_application

    header "Accept", "application/json"
    header "Authorization", set_authorization_header(oauth_token(scopes: "smthelse"))
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_valid_token
    setup_application

    header "Accept", "application/json"
    header "Authorization", set_authorization_header
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  # JSON
  def test_token_access_private_invalid_scope_no_json
    setup_application

    header "Accept", "text/html"
    header "Authorization", set_authorization_header(oauth_token(scopes: "smthelse"))
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 302
    assert last_response.headers["Content-Type"] != "application/json"
  end

  def test_token_access_private_invalid_scope_only_json
    rodauth do
      only_json? true
    end
    setup_application

    header "Authorization", set_authorization_header(oauth_token(scopes: "smthelse"))
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
    assert last_response.headers["Content-Type"] == "application/json"
  end
end
