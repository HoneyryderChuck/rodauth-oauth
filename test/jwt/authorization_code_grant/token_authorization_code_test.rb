# frozen_string_literal: true

require "test_helper"

class RodauthOauthJWTTokenAuthorizationCodeTest < JWTIntegration
  include Rack::Test::Methods

  def test_oauth_jwt_not_jwt_access_token
    rodauth do
      oauth_jwt_keys("HS256" => "SECRET")
      oauth_jwt_access_tokens false
    end
    setup_application

    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    verify_response

    assert db[:oauth_grants].one?
    grant = db[:oauth_grants].first

    assert json_body["token"] = grant[:token]
  end

  def test_oauth_jwt_authorization_code_hmac_sha256
    rodauth do
      oauth_jwt_keys("HS256" => "SECRET")
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
    assert payload["sub"] == account[:id].to_s

    # use token
    header "Authorization", "Bearer #{json_body['access_token']}"

    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  def test_token_authorization_code_hmac_sha256_hash_columns
    rodauth do
      oauth_jwt_keys("HS256" => "SECRET")
      oauth_grants_token_hash_column :token_hash
      oauth_grants_refresh_token_hash_column :refresh_token_hash
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

    assert oauth_grant[:refresh_token].nil?
    assert !oauth_grant[:refresh_token_hash].nil?

    assert json_body["access_token"] != oauth_grant[:token_hash]
    assert json_body["refresh_token"] != oauth_grant[:refresh_token_hash]
    assert !json_body["expires_in"].nil?

    header "Authorization", "Bearer #{json_body['access_token']}"
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  def test_oauth_jwt_authorization_code_jws_rsa_sha256
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
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    verify_response

    oauth_grant = verify_oauth_grant

    verify_access_token_response(json_body, oauth_grant, rsa_public, "RS256")

    # use token
    header "Authorization", "Bearer #{json_body['access_token']}"

    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  unless RUBY_ENGINE == "jruby"
    def test_oauth_jwt_authorization_code_jws_ecdsa_p256
      ecdsa_key = OpenSSL::PKey::EC.generate("prime256v1")
      # OpenSSL 3.0 does not allow construction of public key via another object as before, it is now immutable
      ecdsa_public = ecdsa_key # .public_key

      rodauth do
        oauth_jwt_keys("ES256" => ecdsa_key)
        oauth_jwt_public_keys("ES256" => ecdsa_public)
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

      verify_access_token_response(json_body, oauth_grant, ecdsa_public, "ES256")

      # use token
      header "Authorization", "Bearer #{json_body['access_token']}"

      # valid token, and now we're getting somewhere
      get("/private")
      assert last_response.status == 200
    end
  end # jruby doesn't do ecdsa well

  def test_oauth_jwt_authorization_code_jwe
    jwe_key = OpenSSL::PKey::RSA.new(2048)

    rodauth do
      oauth_jwt_keys("HS256" => "SECRET")
      oauth_jwt_jwe_keys(%w[RSA-OAEP A128CBC-HS256] => jwe_key)
      oauth_jwt_jwe_public_keys(%w[RSA-OAEP A128CBC-HS256] => jwe_key.public_key)
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

    encrypted_token = json_body["access_token"]

    token = JWE.decrypt(encrypted_token, jwe_key)

    verify_access_token_response(json_body.merge("access_token" => token), oauth_grant, "SECRET", "HS256")

    # use token
    header "Authorization", "Bearer #{json_body['access_token']}"

    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  def test_oauth_jwt_authorization_code_legacy_jws
    legacy_rsa_private = OpenSSL::PKey::RSA.generate 2048
    legacy_rsa_public = legacy_rsa_private.public_key

    # Get Legacy Token
    rodauth do
      oauth_jwt_keys { { "RS256" => legacy_rsa_private } }
    end
    setup_application

    with_session(:legacy) do
      post("/token",
           client_id: oauth_application[:client_id],
           client_secret: "CLIENT_SECRET",
           grant_type: "authorization_code",
           code: oauth_grant[:code],
           redirect_uri: oauth_grant[:redirect_uri])

      verify_response

      oauth_grant = verify_oauth_grant
      verify_access_token_response(json_body, oauth_grant, legacy_rsa_public, "RS256")
    end

    # Set up new app and tokens
    # Get Legacy Token
    # Resource server
    @rodauth_blocks.clear
    rodauth do
      oauth_jwt_keys("RS256" => legacy_rsa_public)
    end
    setup_application

    with_session(:rotated) do
      # use legacy access token
      header "Authorization", "Bearer #{json_body['access_token']}"
      header "Accept", "application/json"

      # valid access
      current_session.get("/private")
      assert last_response.status == 200
    end
  end

  private

  def setup_application(*)
    super
    rodauth do
      oauth_jwt_keys("HS256" => OpenSSL::PKey::RSA.new(2048))
    end
    header "Accept", "application/json"
  end
end
