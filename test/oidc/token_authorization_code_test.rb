# frozen_string_literal: true

require "test_helper"

class RodauthOAuthOidcTokenAuthorizationCodeTest < OIDCIntegration
  include Rack::Test::Methods

  def test_token_authorization_code_with_nonce
    setup_application

    grant = oauth_grant(nonce: "NONCE")

    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: grant[:code],
         redirect_uri: grant[:redirect_uri])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_grants].count == 1

    oauth_grant = db[:oauth_grants].first

    assert oauth_grant[:nonce] == "NONCE", "nonce should be passed to token"
  end

  private

  def setup_application(*)
    rodauth do
      oauth_jwt_key OpenSSL::PKey::RSA.generate(2048)
      oauth_jwt_algorithm "RS256"
    end
    super
    header "Accept", "application/json"
  end
end
