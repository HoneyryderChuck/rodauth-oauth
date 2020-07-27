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

    assert db[:oauth_tokens].count == 1

    access_token = db[:oauth_tokens].first

    oauth_grant = db[:oauth_grants].where(id: access_token[:oauth_grant_id]).first
    assert !oauth_grant[:revoked_at].nil?, "oauth grant should be revoked"
    assert oauth_grant[:nonce] == "NONCE", "nonce should be passed to token"
  end

  private

  def setup_application
    super
    header "Accept", "application/json"
  end
end
