# frozen_string_literal: true

require "test_helper"

class RodauthClientCredentialsGrantOAuthTokenAccessTest < RodaIntegration
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
    set_authorization_header(oauth_grant_with_token(revoked_at: Sequel::CURRENT_TIMESTAMP))
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_expired_token
    setup_application

    header "Accept", "application/json"
    set_authorization_header(oauth_grant_with_token(expires_in: Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, seconds: 20)))
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_invalid_scope
    setup_application

    header "Accept", "application/json"
    set_authorization_header(oauth_grant_with_token(scopes: "smthelse"))
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
    assert last_response["x-oauth-subject"] == oauth_application[:id]
  end

  def test_token_access_private_invalid_scope_only_json
    rodauth do
      only_json? true
    end
    setup_application

    set_authorization_header(oauth_grant_with_token(scopes: "smthelse"))
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
    assert last_response["x-oauth-subject"] == oauth_application[:id]
  end

  private

  def oauth_feature
    :oauth_client_credentials_grant
  end

  def set_oauth_grant_with_token(params = {})
    super(params.merge(account_id: nil))
  end
end
