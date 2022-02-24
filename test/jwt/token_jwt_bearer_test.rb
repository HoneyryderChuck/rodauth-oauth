# frozen_string_literal: true

require "test_helper"

class RodauthOauthJWTTokenJwtBearerTest < JWTIntegration
  include Rack::Test::Methods

  def test_oauth_jwt_as_authorization_grant
    rodauth do
      use_oauth_jwt_bearer_grant_type? true
      oauth_jwt_key "SECRET"
      oauth_jwt_algorithm "HS256"
    end
    setup_application

    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    verify_response

    jwt_token = json_body["access_token"]
    @json_body = nil
    sleep 1

    # use token as assertion
    post("/token",
         grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
         assertion: jwt_token)

    verify_response

    jwt_token2 = json_body["access_token"]

    assert jwt_token2 != jwt_token

    # use token
    header "Authorization", "Bearer #{jwt_token2}"

    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  private

  def oauth_feature
    :oauth_jwt_bearer_grant
  end
end
