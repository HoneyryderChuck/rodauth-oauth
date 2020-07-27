# frozen_string_literal: true

require "test_helper"

class RodauthOauthJwtTokenRevokeTest < JWTIntegration
  include Rack::Test::Methods

  def test_oauth_token_revoke_access_token
    setup_application
    login

    # generate jwt
    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    verify_response

    post("/revoke", token_type_hint: "access_token", token: json_body["access_token"])

    assert last_response.status == 400
  end

  def test_oauth_token_revoke_refresh_token
    setup_application
    login

    post("/revoke", token_type_hint: "access_token", token: oauth_token[:refresh_token])

    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"

    post("/revoke", token_type_hint: "refresh_token", token: oauth_token[:refresh_token])

    assert last_response.status == 200
    assert db[:oauth_tokens].where(revoked_at: nil).count.zero?
  end

  private

  # overriding to implement the client/secret basic authorization
  def login
    header "Authorization", "Basic #{authorization_header(
      username: oauth_application[:client_id],
      password: 'CLIENT_SECRET'
    )}"
  end

  def setup_application
    super
    header "Accept", "application/json"
  end

  def post(uri, params = {}, _env = {}, &block)
    header "Content-Type", "application/json"
    super(uri, {}, { input: params.to_json }, &block)
  end
end
