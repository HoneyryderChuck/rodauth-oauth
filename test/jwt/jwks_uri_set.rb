# frozen_string_literal: true

require "test_helper"

class RodauthOauthJwtJwksUriTest < JWTIntegration
  include Rack::Test::Methods

  def test_oauth_jwt_jwks_no_key
    rodauth do
      oauth_jwt_algorithm "HS256"
    end
    setup_application
    get("/oauth-jwks")

    assert last_response.status == 200
    assert json_body == []
  end

  def test_oauth_jwt_jwks_signing_key
    priv_key = OpenSSL::PKey::RSA.new(2048)
    pub_key = priv_key.public_key

    rodauth do
      oauth_jwt_jwk_key priv_key
      oauth_jwt_jwk_public_key pub_key
      oauth_jwt_algorithm "RS256"
    end
    setup_application
    get("/oauth-jwks")

    assert last_response.status == 200
    assert json_body[0]["use"] == "sig"
    assert json_body[0]["alg"] == "RS256"
    assert json_body[0]["kty"] == "RSA"
    assert json_body[0].key?("kid")
  end

  def test_oauth_jwt_jwks_encryption_key
    priv_key = OpenSSL::PKey::RSA.new(2048)
    pub_key = priv_key.public_key

    jwe_key = OpenSSL::PKey::RSA.new(2048)
    jwe_pub_key = jwe_key.public_key

    rodauth do
      oauth_jwt_jwk_key priv_key
      oauth_jwt_jwk_public_key pub_key
      oauth_jwt_algorithm "RS256"
      oauth_jwt_jwe_key jwe_key
      oauth_jwt_jwe_public_key jwe_pub_key
      oauth_jwt_jwe_algorithm "RSA-OAEP"
      oauth_jwt_jwe_encryption_method "A256GCM"
    end
    setup_application
    get("/oauth-jwks")

    assert last_response.status == 200
    assert json_body[0]["use"] == "sig"
    assert json_body[0]["alg"] == "RS256"
    assert json_body[0]["kty"] == "RSA"
    assert json_body[0].key?("kid")

    assert json_body[1]["use"] == "enc"
    assert json_body[1]["alg"] == "RSA-OAEP"
    assert json_body[1]["kty"] == "RSA"
    assert json_body[1].key?("kid")
  end
end
