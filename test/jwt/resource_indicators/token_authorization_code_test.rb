# frozen_string_literal: true

require "test_helper"

class RodauthOauthResourceIndicatorsJWTTokenAuthorizationCodeTest < JWTIntegration
  include Rack::Test::Methods

  def test_oauth_jwt_authorization_code_resource_indicators
    rsa_private = OpenSSL::PKey::RSA.generate 2048
    rsa_public = rsa_private.public_key
    rodauth do
      enable :oauth_resource_indicators
      oauth_jwt_key rsa_private
      oauth_jwt_public_key rsa_public
      oauth_jwt_algorithm "RS256"
    end
    setup_application

    oauth_grant = set_oauth_grant(resource: "https://example.com")

    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         resource: "https://example.com",
         redirect_uri: oauth_grant[:redirect_uri])

    verify_response

    oauth_token = verify_oauth_token

    verify_access_token_response(json_body, oauth_token, rsa_public, "RS256", audience: %w[https://example.com])

    # use token
    header "Authorization", "Bearer #{json_body['access_token']}"

    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  private

  def setup_application
    super
    header "Accept", "application/json"
  end
end
