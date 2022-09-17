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

  def test_oidc_authorization_code_hmac_sha256_subject_pairwise
    rodauth do
      oauth_jwt_keys("HS256" => "SECRET")
      oauth_jwt_subject_type "pairwise"
    end
    setup_application

    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    verify_response

    oauth_grant = verify_oauth_grant

    payload = verify_access_token_response(json_body, oauth_grant, "SECRET", "HS256")
    # by default the subject type is public
    assert payload["sub"] != account[:id]

    # use token
    header "Authorization", "Bearer #{json_body['access_token']}"

    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  private

  def setup_application(*)
    rodauth do
      oauth_jwt_keys("RS256" => OpenSSL::PKey::RSA.generate(2048))
    end
    super
    header "Accept", "application/json"
  end
end
