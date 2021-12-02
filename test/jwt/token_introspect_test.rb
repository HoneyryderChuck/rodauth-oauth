# frozen_string_literal: true

require "test_helper"

class RodauthOauthJwtTokenIntrospectTest < JWTIntegration
  include Rack::Test::Methods

  def test_oauth_introspect_access_token
    rodauth do
      oauth_jwt_key "SECRET"
      oauth_jwt_algorithm "HS256"
    end
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

    # valid token, and now we're getting somewhere
    post("/introspect", {
           token: json_body["access_token"],
           token_type_hint: "access_token"
         })

    @json_body = nil
    verify_response

    oauth_token = verify_oauth_token

    assert json_body["active"] == true
    assert json_body["scope"] == oauth_token[:scopes]
    assert json_body["client_id"] == oauth_application[:client_id]
    assert json_body["token_type"] == "access_token"
    assert json_body.key?("exp")

    # test all other jwt props
    assert json_body.key?("exp")
    assert json_body.key?("iat")
    assert json_body.key?("nbf")
    assert json_body.key?("sub")
    assert json_body.key?("aud")
    assert json_body.key?("iss")
    assert json_body.key?("jti")
  end

  private

  def setup_application
    super
    header "Accept", "application/json"
  end

  # overriding to implement the client/secret basic authorization
  def login
    header "Authorization", "Basic #{authorization_header(
      username: oauth_application[:client_id],
      password: 'CLIENT_SECRET'
    )}"
  end
end
