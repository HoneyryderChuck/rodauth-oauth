# frozen_string_literal: true

require_relative File.join(__dir__, "jwt_integration")

class OIDCIntegration < JWTIntegration
  private

  def oauth_application(params = {})
    super({ scopes: "openid" }.merge(params))
  end

  def oauth_grant(params = {})
    super({ scopes: "openid" }.merge(params))
  end

  def oauth_token(params = {})
    super({ scopes: "openid" }.merge(params))
  end

  def test_scopes
    %w[openid]
  end

  def oauth_feature
    :oidc
  end

  def verify_access_token_response(data, oauth_token, secret, algorithm)
    super
    assert data.key?("id_token")
    payload, headers = JWT.decode(data["id_token"], secret, true, algorithms: [algorithm])

    assert headers["alg"] == algorithm
    assert payload["nonce"] == oauth_token[:nonce]
    assert payload["iss"] == "http://example.org"
    assert payload["sub"] == account[:id]
    assert payload.key?("aud")
    assert payload.key?("exp")
    assert payload.key?("iat")
  end
end
