# frozen_string_literal: true

require ENV["JWT_LIB"] if ENV["JWT_LIB"]
require "jwt"
require "jwe"
require_relative File.join(__dir__, "roda_integration")

class JWTIntegration < RodaIntegration
  private

  def oauth_feature
    :oauth_jwt
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

  def verify_access_token_response(data, oauth_token, secret, algorithm, audience: "CLIENT_ID")
    verify_token_common_response(data)

    assert data.key?("access_token")
    verify_access_token(data["access_token"], oauth_token, signing_key: secret, signing_algo: algorithm, audience: audience)
  end

  def verify_access_token(data, oauth_token, signing_key:, signing_algo:, audience: "CLIENT_ID")
    claims, headers = JWT.decode(data, signing_key, true, algorithms: [signing_algo])
    assert headers["alg"] == signing_algo

    verify_jwt_claims(claims, oauth_token, audience: audience)
    assert claims.key?("client_id")
    assert claims["client_id"] == "CLIENT_ID"
    claims
  end

  def verify_jwt_claims(claims, _oauth_token, audience: "CLIENT_ID")
    assert claims.key?("iss")
    if respond_to?(:last_response)
      assert claims["iss"] == "http://example.org"
    else
      assert claims["iss"] == "http://www.example.com"
    end
    assert claims.key?("sub")
    assert claims.key?("aud")
    assert claims["aud"] == audience
    assert claims.key?("exp")
    assert claims.key?("iat")
    assert claims.key?("jti")
  end

  def generate_signed_request(application,
                              signing_key: OpenSSL::PKey::RSA.generate(2048),
                              signing_algorithm: "RS256",
                              encryption_key: nil,
                              encryption_method: "A128CBC-HS256",
                              encryption_algorithm: "RSA-OAEP", **extra_claims)
    claims = {
      iss: "http://www.example.com",
      aud: "http://www.example.com",
      response_type: "code",
      client_id: application[:client_id],
      redirect_uri: application[:redirect_uri],
      scope: application[:scopes],
      state: "ABCDEF"
    }.merge(extra_claims)

    headers = {}

    jwk = JWT::JWK.new(signing_key)
    headers[:kid] = jwk.kid

    signing_key = jwk.keypair

    token = JWT.encode(claims, signing_key, signing_algorithm, headers)

    if encryption_key
      jwk = JWT::JWK.new(encryption_key)
      params = {
        enc: encryption_method,
        alg: encryption_algorithm,
        kid: jwk.kid
      }
      token = JWE.encrypt(token, encryption_key, **params)
    end

    token
  end
end
