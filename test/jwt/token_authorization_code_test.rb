# frozen_string_literal: true

require "test_helper"

class RodaOauthJWTTokenAuthorizationCodeTest < JWTIntegration
  include Rack::Test::Methods

  def test_oauth_jwt_authorization_code_hmac_sha256
    rodauth do
      oauth_jwt_key "SECRET"
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

    verify_response_body(json_body, oauth_token, "SECRET", "HS256")

    # use token
    header "Authorization", "Bearer #{json_body['access_token']}"

    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  def test_oauth_jwt_authorization_code_jws_rsa_sha256
    rsa_private = OpenSSL::PKey::RSA.generate 2048
    rsa_public = rsa_private.public_key
    rodauth do
      oauth_jwt_key rsa_private
      oauth_jwt_public_key rsa_public
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

    verify_response_body(json_body, oauth_token, rsa_public, "RS256")

    # use token
    header "Authorization", "Bearer #{json_body['access_token']}"

    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  unless RUBY_ENGINE == "jruby"
    def test_oauth_jwt_authorization_code_jws_ecdsa_p256
      ecdsa_key = OpenSSL::PKey::EC.new "prime256v1"
      ecdsa_key.generate_key
      ecdsa_public = OpenSSL::PKey::EC.new ecdsa_key
      ecdsa_public.private_key = nil

      rodauth do
        oauth_jwt_key ecdsa_key
        oauth_jwt_public_key ecdsa_public
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

      verify_response_body(json_body, oauth_token, ecdsa_public, "ES256")

      # use token
      header "Authorization", "Bearer #{json_body['access_token']}"

      # valid token, and now we're getting somewhere
      get("/private")
      assert last_response.status == 200
    end
  end # jruby doesn't do ecdsa well

  def test_oauth_jwt_authorization_code_jwk
    jwk_key = OpenSSL::PKey::RSA.new(2048)

    rodauth do
      oauth_jwt_jwk_key jwk_key
      oauth_jwt_jwk_public_key jwk_key.public_key
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

    verify_response_body(json_body, oauth_token, jwk_key, "RS256")

    # use token
    header "Authorization", "Bearer #{json_body['access_token']}"

    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  def test_oauth_jwt_authorization_code_jwe
    jwe_key = OpenSSL::PKey::RSA.new(2048)

    rodauth do
      oauth_jwt_key "SECRET"
      oauth_jwt_algorithm "HS256"
      oauth_jwt_jwe_key jwe_key
      oauth_jwt_jwe_public_key jwe_key.public_key
      oauth_jwt_jwe_algorithm "RSA-OAEP"
      oauth_jwt_jwe_encryption_method "A256GCM"
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

    encrypted_token = json_body["access_token"]

    token = JWE.decrypt(encrypted_token, jwe_key)

    verify_response_body(json_body.merge("access_token" => token), oauth_token, "SECRET", "HS256")

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
