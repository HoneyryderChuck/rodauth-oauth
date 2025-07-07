# frozen_string_literal: true

require "test_helper"

class RodauthJWTClientCredentialsGrantOAuthTokenAuthorizationCodeTest < JWTIntegration
  include Rack::Test::Methods

  def test_token_authorization_code_no_client_secret
    setup_application

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "client_credentials")

    assert last_response.status == 401
    assert json_body["error"] == "invalid_client"
  end

  def test_token_authorization_code_successful
    rsa_private = OpenSSL::PKey::RSA.generate 2048
    rsa_public = rsa_private.public_key
    rodauth do
      oauth_jwt_keys("RS256" => rsa_private)
      oauth_jwt_public_keys("RS256" => rsa_public)
    end
    setup_application

    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "client_credentials")

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_grants].one?

    oauth_grant = db[:oauth_grants].first

    verify_access_token_response(json_body, oauth_grant, rsa_public, "RS256")

    assert !json_body.key?("refresh_token")

    # use token
    header "Authorization", "Bearer #{json_body['access_token']}"

    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  private

  def setup_application(*)
    super
    header "Accept", "application/json"
  end

  def oauth_feature
    %i[oauth_client_credentials_grant oauth_jwt]
  end
end
