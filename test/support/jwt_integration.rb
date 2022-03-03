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

  def verify_access_token_response(data, oauth_token, secret, algorithm)
    verify_token_common_response(data)
    assert data["refresh_token"] == oauth_token[:refresh_token]

    assert data.key?("access_token")
    payload, headers = JWT.decode(data["access_token"], secret, true, algorithms: [algorithm])

    assert headers["alg"] == algorithm
    assert payload["iss"] == "http://example.org"
    assert payload["aud"] == "CLIENT_ID"
    assert payload["nonce"] == oauth_token[:nonce]
    payload
  end
end
