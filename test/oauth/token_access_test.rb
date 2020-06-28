# frozen_string_literal: true

require "test_helper"

class RodauthOAuthTokenAuthorizationCodeTest < RodaIntegration
  include Rack::Test::Methods

  def test_token_access_private_revoked_token
    setup_application

    header "Accept", "application/json"
    set_authorization_header(oauth_token(revoked_at: Time.now))
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_expired_token
    setup_application

    header "Accept", "application/json"
    set_authorization_header(oauth_token(expires_in: Time.now - 20))
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_invalid_scope
    setup_application

    header "Accept", "application/json"
    set_authorization_header(oauth_token(scopes: "smthelse"))
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_valid_token
    setup_application

    header "Accept", "application/json"
    set_authorization_header
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  # JSON
  def test_token_access_private_invalid_scope_no_json
    setup_application

    header "Accept", "text/html"
    set_authorization_header(oauth_token(scopes: "smthelse"))
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

    set_authorization_header(oauth_token(scopes: "smthelse"))
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
    assert last_response.headers["Content-Type"] == "application/json"
  end

  def test_token_access_private_from_query_params
    rodauth do
      fetch_access_token { param_or_nil("access_token") }
    end
    setup_application

    header "Accept", "application/json"

    get("/private", access_token: oauth_token[:token])
    assert last_response.status == 200
  end
end
