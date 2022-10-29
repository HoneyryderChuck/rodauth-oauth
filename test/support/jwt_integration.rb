# frozen_string_literal: true

require ENV["JWT_LIB"] if ENV["JWT_LIB"]
require "jwt"
require "jwe"
require_relative File.join(__dir__, "roda_integration")

class JWTIntegration < RodaIntegration
  private

  def oauth_feature
    %i[oauth_authorization_code_grant oauth_jwt]
  end

  def set_oauth_grant_with_token(params = {})
    super({
      token: nil,
      refresh_token: "REFRESH_TOKEN",
      code: nil
    }.merge(params))
  end

  def verify_oauth_grant
    assert db[:oauth_grants].count == 1

    oauth_grant = db[:oauth_grants].first

    assert oauth_grant[:token].nil?

    oauth_grant
  end

  def verify_response(status = 200)
    assert last_response.status == status
    assert last_response.headers["Content-Type"] == "application/json"
  end

  def verify_access_token_response(data, oauth_grant, secret, algorithm, audience: "CLIENT_ID")
    verify_token_common_response(data)

    assert data.key?("access_token")
    verify_access_token(data["access_token"], oauth_grant, signing_key: secret, signing_algo: algorithm, audience: audience)
  end

  def verify_access_token(data, oauth_grant, signing_key:, signing_algo:, audience: "CLIENT_ID")
    claims, headers = JWT.decode(data, signing_key, true, algorithms: [signing_algo])
    assert headers["alg"] == signing_algo

    assert claims.key?("client_id")
    assert claims["client_id"] == "CLIENT_ID"
    assert claims["scope"] == oauth_grant[:scopes]
    verify_jwt_claims(claims, oauth_grant, audience: audience)
    claims
  end

  def verify_jwt_claims(claims, _oauth_grant, audience: claims["client_id"])
    assert claims.key?("iss")
    assert claims["iss"] == example_origin
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
      response_mode: "query",
      response_type: "code",
      client_id: application[:client_id],
      redirect_uri: application[:redirect_uri],
      scope: application[:scopes],
      state: "ABCDEF"
    }.merge(extra_claims).compact

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

  def example_origin
    if respond_to?(:last_response)
      "http://example.org"
    else
      "http://www.example.com"
    end
  end
end
