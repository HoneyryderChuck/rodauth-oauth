# frozen_string_literal: true

require "test_helper"

class RodauthOAuthTokenRevokeTest < RodaIntegration
  include Rack::Test::Methods

  def test_revoke_invalid_hint
    setup_application
    login
    post("/revoke", token_type_hint: "hinterz", token: "CODE")

    assert last_response.status == 400
    assert json_body["error"] == "unsupported_token_type"
  end

  def test_revoke_no_token
    setup_application
    login
    post("/revoke", token_type_hint: "access_token", token: "CODE")

    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
  end

  def test_revoke_revoked_token
    setup_application
    login
    oauth_grant = oauth_grant_with_token(revoked_at: Sequel::CURRENT_TIMESTAMP)

    post("/revoke", token_type_hint: "access_token", token: oauth_grant[:token])

    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
  end

  def test_revoke_access_token
    setup_application
    login

    post("/revoke", token_type_hint: "access_token", token: oauth_grant_with_token[:token])

    assert last_response.status == 200
    assert db[:oauth_grants].where(revoked_at: nil).none?
  end

  def test_revoke_refresh_token
    setup_application
    login

    post("/revoke", token_type_hint: "access_token", token: oauth_grant_with_token[:refresh_token])

    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"

    post("/revoke", token_type_hint: "refresh_token", token: oauth_grant_with_token[:refresh_token])

    assert last_response.status == 200
    assert db[:oauth_grants].where(revoked_at: nil).none?
  end

  private

  # overriding to implement the client/secret basic authorization
  def login
    header "Authorization", "Basic #{authorization_header(
      username: oauth_application[:client_id],
      password: 'CLIENT_SECRET'
    )}"
  end

  def oauth_feature
    :oauth_token_revocation
  end

  def setup_application(*)
    super
    header "Accept", "application/json"
  end

  def post(uri, params = {}, _env = {}, &block)
    header "Content-Type", "application/json"
    super(uri, {}, { input: params.to_json }, &block)
  end
end
