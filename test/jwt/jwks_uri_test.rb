# frozen_string_literal: true

require "test_helper"

class RodauthOauthJwtJwksUriTest < JWTIntegration
  include Rack::Test::Methods

  def test_oauth_jwt_jwks_no_key
    setup_application
    get("/jwks")

    assert last_response.status == 200
    assert json_body == { "keys" => [] }
  end

  def test_oauth_jwt_jwks_signing_key
    priv_key = OpenSSL::PKey::RSA.new(2048)
    pub_key = priv_key.public_key

    rodauth do
      oauth_jwt_keys("RS256" => priv_key)
      oauth_jwt_public_keys("RS256" => pub_key)
    end
    setup_application
    get("/jwks")

    assert last_response.status == 200
    assert json_body["keys"][0]["use"] == "sig"
    assert json_body["keys"][0]["alg"] == "RS256"
    assert json_body["keys"][0]["kty"] == "RSA"
    assert json_body["keys"][0].key?("kid")
  end

  def test_oauth_jwt_jwks_encryption_key
    priv_key = OpenSSL::PKey::RSA.new(2048)
    pub_key = priv_key.public_key

    jwe_key = OpenSSL::PKey::RSA.new(2048)
    jwe_pub_key = jwe_key.public_key

    rodauth do
      oauth_jwt_keys("RS256" => priv_key)
      oauth_jwt_public_keys("RS256" => pub_key)
      oauth_jwt_jwe_keys(%w[RSA-OAEP A128CBC-HS256] => jwe_key)
      oauth_jwt_jwe_public_keys(%w[RSA-OAEP A128CBC-HS256] => jwe_pub_key)
    end
    setup_application
    get("/jwks")

    assert last_response.status == 200
    assert json_body["keys"][0]["use"] == "sig"
    assert json_body["keys"][0]["alg"] == "RS256"
    assert json_body["keys"][0]["kty"] == "RSA"
    assert json_body["keys"][0].key?("kid")

    assert json_body["keys"][1]["use"] == "enc"
    assert json_body["keys"][1]["alg"] == "RSA-OAEP"
    assert json_body["keys"][1]["kty"] == "RSA"
    assert json_body["keys"][1].key?("kid")
  end
end
