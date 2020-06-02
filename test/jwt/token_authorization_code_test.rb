# frozen_string_literal: true

require "test_helper"

class RodaOauthJWTTokenAuthorizationCodeTest < JWTIntegration
  include Rack::Test::Methods

  def test_oauth_jwt_authorization_code_hmac_sha256
    rodauth do
      oauth_jwt_secret "SECRET"
      oauth_jwt_algorithm "HS256"
    end
    setup_application

    post("/oauth-token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    verify_response

    oauth_token = verify_oauth_token

    json_body = JSON.parse(last_response.body)

    verify_response_body(json_body, oauth_token, "SECRET", "HS256")

    # use token
    header "Authorization", "Bearer #{json_body["access_token"]}"

    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  def test_oauth_jwt_authorization_code_jws_rsa_sha256
    rsa_private = OpenSSL::PKey::RSA.generate 2048
    rsa_public = rsa_private.public_key
    rodauth do
      oauth_jwt_secret rsa_private
      oauth_jwt_decoding_secret rsa_public
      oauth_jwt_algorithm "RS256"
    end
    setup_application

    post("/oauth-token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    verify_response

    oauth_token = verify_oauth_token

    json_body = JSON.parse(last_response.body)

    verify_response_body(json_body, oauth_token, rsa_public, "RS256")

    # use token
   header "Authorization", "Bearer #{json_body["access_token"]}"

    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  def test_oauth_jwt_authorization_code_jws_ecdsa_p256
    ecdsa_key = OpenSSL::PKey::EC.new 'prime256v1'
    ecdsa_key.generate_key
    ecdsa_public = OpenSSL::PKey::EC.new ecdsa_key
    ecdsa_public.private_key = nil

    rodauth do
      oauth_jwt_secret ecdsa_key
      oauth_jwt_decoding_secret ecdsa_public
      oauth_jwt_algorithm "ES256"
    end
    setup_application

    post("/oauth-token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    verify_response

    oauth_token = verify_oauth_token

    json_body = JSON.parse(last_response.body)

    verify_response_body(json_body, oauth_token, ecdsa_public, "ES256")

    # use token
   header "Authorization", "Bearer #{json_body["access_token"]}"

    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  def test_oauth_jwt_authorization_code_jwk
    jwk_key = OpenSSL::PKey::RSA.new(2048)

    rodauth do
      oauth_jwt_jwk_key jwk_key
      oauth_jwt_algorithm "RS512"
    end
    setup_application

    post("/oauth-token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    verify_response

    oauth_token = verify_oauth_token

    json_body = JSON.parse(last_response.body)

    verify_response_body(json_body, oauth_token, jwk_key, "RS512")

    # use token
   header "Authorization", "Bearer #{json_body["access_token"]}"

    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  def test_oauth_jwt_authorization_code_jwe; end

  private

  def setup_application
    super
    header "Accept", "application/json"
  end

  def verify_oauth_token
    assert db[:oauth_tokens].count == 1

    oauth_token = db[:oauth_tokens].first

    assert oauth_token[:token].nil?

    oauth_grant = db[:oauth_grants].where(id: oauth_token[:oauth_grant_id]).first
    assert !oauth_grant[:revoked_at].nil?, "oauth grant should be revoked"

    oauth_token
  end

  def verify_response
    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"
  end

  def verify_response_body(data, oauth_token, secret, algorithm)
    assert data["refresh_token"] == oauth_token[:refresh_token]

    assert !data["expires_in"].nil?
    assert data["token_type"] == "bearer"

    payload, headers = JWT.decode(data["access_token"], secret, true, algorithms: [algorithm])

    assert headers["alg"] == algorithm
    assert payload["iss"] == "Example"
    assert payload["sub"] == account[:id]
  end
end
