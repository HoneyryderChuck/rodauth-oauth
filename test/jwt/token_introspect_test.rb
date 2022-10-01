# frozen_string_literal: true

require "test_helper"

class RodauthOauthJwtTokenIntrospectTest < JWTIntegration
  include Rack::Test::Methods

  def test_oauth_introspect_access_token
    rodauth do
      oauth_jwt_keys("HS256" => "SECRET")
    end
    setup_application(:oauth_token_introspection)
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

    oauth_grant = verify_oauth_grant

    assert json_body["active"] == true
    assert json_body["username"] == account[:email]
    assert json_body["scope"] == oauth_grant[:scopes]
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

  def test_oauth_introspect_access_token_client_credentials
    rodauth do
      oauth_jwt_keys("HS256" => "SECRET")
    end
    setup_application(:oauth_client_credentials_grant, :oauth_token_introspection)
    login

    # generate jwt
    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "client_credentials")

    verify_response

    # valid token, and now we're getting somewhere
    post("/introspect", {
           token: json_body["access_token"],
           token_type_hint: "access_token"
         })

    @json_body = nil
    verify_response

    oauth_grant = verify_oauth_grant

    assert json_body["active"] == true
    assert json_body["username"] == "Foo"
    assert json_body["scope"] == oauth_grant[:scopes]
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

  def test_oauth_introspect_access_with_token_client_credentials_auth
    rodauth do
      oauth_jwt_keys("HS256" => "SECRET")
    end
    setup_application(:oauth_client_credentials_grant, :oauth_token_introspection)

    # generate client credentials token
    # generate jwt
    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "client_credentials")

    verify_response
    client_token = json_body["access_token"]

    # generate jwt
    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    @json_body = nil
    verify_response

    access_token = json_body["access_token"]

    header "Authorization", "Bearer #{client_token}"

    # valid token, and now we're getting somewhere
    post("/introspect", { token: access_token, token_type_hint: "access_token" })

    @json_body = nil
    verify_response

    assert json_body["active"] == true
    assert json_body["username"] == account[:email]
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

  def oauth_feature
    %i[oauth_authorization_code_grant oauth_token_introspection oauth_jwt]
  end

  def setup_application(*)
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
