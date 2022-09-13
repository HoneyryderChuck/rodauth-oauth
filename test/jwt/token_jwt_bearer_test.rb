# frozen_string_literal: true

require "test_helper"

class RodauthOauthJWTTokenJwtBearerTest < JWTIntegration
  include Rack::Test::Methods

  def test_oauth_jwt_bearer_as_authorization_grant
    rodauth do
      oauth_jwt_keys("HS256" => "SECRET")
    end
    setup_application

    post("/token",
         grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
         assertion: jwt_assertion(account[:email], "HS256", "SECRET"))

    verify_response

    jwt_token = json_body["access_token"]

    # use token
    header "Authorization", "Bearer #{jwt_token}"

    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  def test_oauth_jwt_bearer_as_client_authentication_behalf_of_itself
    rodauth do
      oauth_jwt_keys("HS256" => "SECRET")
    end
    setup_application(:oauth_authorization_code_grant)

    grant = set_oauth_grant(type: "authorization_code")

    post("/token",
         client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
         client_assertion: jwt_assertion(oauth_application[:client_id], "HS256", "SECRET"),
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: grant[:code],
         redirect_uri: grant[:redirect_uri])

    verify_response

    jwt_token = json_body["access_token"]

    # use token
    header "Authorization", "Bearer #{jwt_token}"

    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  private

  def oauth_feature
    :oauth_jwt_bearer_grant
  end

  def default_grant_type
    "jwt-bearer"
  end

  def jwt_assertion(principal, algo, signing_key, extra_claims = {})
    claims = {
      iss: oauth_application[:client_id],
      # client_id: oauth_application[:client_id],
      aud: "http://example.org/token",
      sub: principal,
      iat: Time.now.to_i, # issued at
      exp: Time.now.to_i + 3600
    }.merge(extra_claims)
    claims[:jti] = Digest::SHA256.hexdigest("#{claims[:aud]}:#{claims[:iat]}")

    headers = {}

    jwk = JWT::JWK.new(signing_key)
    headers[:kid] = jwk.kid

    signing_key = jwk.keypair

    JWT.encode(claims, signing_key, algo, headers)
  end

  def setup_application(*)
    super
    header "Accept", "application/json"
  end
end
