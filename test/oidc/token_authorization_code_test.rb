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

    verify_response

    oauth_token = verify_oauth_token
    oauth_grant = db[:oauth_grants].where(id: oauth_token[:oauth_grant_id]).first
    assert oauth_grant[:nonce] == "NONCE", "nonce should be passed to token"

    verify_access_token_response(json_body, oauth_token, "SECRET", "HS256")
  end

  private

  def setup_application
    rodauth do
      oauth_jwt_key "SECRET"
      oauth_jwt_algorithm "HS256"
    end
    super
    header "Accept", "application/json"
  end
end
