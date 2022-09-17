# frozen_string_literal: true

require "test_helper"

class RodauthOAuthTokenAccessTest < RodaIntegration
  include Rack::Test::Methods

  def test_token_access_private_no_token
    setup_application

    header "Accept", "application/json"
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_empty_token
    setup_application

    header "Accept", "application/json"
    header "Authorization", ""
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_empty_bearer_token
    setup_application

    header "Accept", "application/json"
    header "Authorization", "Bearer "
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_revoked_token
    setup_application

    header "Accept", "application/json"
    set_authorization_header(oauth_grant(revoked_at: Sequel::CURRENT_TIMESTAMP))
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_expired_token
    setup_application

    header "Accept", "application/json"
    set_authorization_header(oauth_grant(expires_in: Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, seconds: 20)))
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_invalid_scope
    setup_application

    header "Accept", "application/json"
    set_authorization_header(oauth_grant(scopes: "smthelse"))
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
    assert last_response["x-oauth-subject"] == account[:id]
    assert last_response["x-oauth-current-account"] == account[:id]
    assert last_response["x-oauth-current-application"] == "CLIENT_ID"
  end

  # JSON
  def test_token_access_private_invalid_scope_no_json
    setup_application

    header "Accept", "text/html"
    set_authorization_header(oauth_grant(scopes: "smthelse"))
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

    set_authorization_header(oauth_grant(scopes: "smthelse"))
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

    get("/private", access_token: oauth_grant_with_token[:token])
    assert last_response.status == 200
    assert last_response["x-oauth-subject"] == account[:id]
  end

  private

  def oauth_feature
    :oauth_authorization_code_grant
  end
end
