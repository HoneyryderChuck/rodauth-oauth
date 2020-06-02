# frozen_string_literal: true

require "test_helper"

class RodaOauthJWTTokenAuthorizationCodeTest < JWTIntegration
  include Rack::Test::Methods

  def test_oauth_jwt_authorization_code_hmac_sha256
    rodauth do
      oauth_jwt_secret "SECRET"
      oauth_jwt_algorithm "HS256"
    end
    setup_application

    code = oauth_grant[:code]
    post("/oauth-token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: code,
         redirect_uri: oauth_grant[:redirect_uri])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_tokens].count == 1

    oauth_token = db[:oauth_tokens].first

    assert oauth_token[:token].nil?

    oauth_grant = db[:oauth_grants].where(id: oauth_token[:oauth_grant_id]).first
    assert !oauth_grant[:revoked_at].nil?, "oauth grant should be revoked"

    json_body = JSON.parse(last_response.body)
    token = json_body["access_token"]

    payload, headers = JWT.decode(token, "SECRET", true, algorithms: %w[HS256])
    assert headers["alg"] == "HS256"
    assert payload["iss"] == "Example"
    assert payload["sub"] == account[:id]

    assert json_body["refresh_token"] == oauth_token[:refresh_token]

    assert !json_body["expires_in"].nil?
    assert json_body["token_type"] == "bearer"

    # use token

    header "Authorization", "Bearer #{json_body['access_token']}"
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  def test_oauth_jwt_authorization_code_jws_rsa_sha256; end

  def test_oauth_jwt_authorization_code_jws_ecdsa_p256; end

  def test_oauth_jwt_authorization_code_jwk; end

  def test_oauth_jwt_authorization_code_jwe; end

  private

  def setup_application
    super
    header "Accept", "application/json"
  end
end
