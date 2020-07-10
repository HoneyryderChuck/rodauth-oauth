# frozen_string_literal: true

require_relative File.join(__dir__, "jwt_integration")

class OIDCIntegration < JWTIntegration
  private

  def oauth_application(params = {})
    super({ scopes: "openid" }.merge(params))
  end

  def test_scopes
    %w[openid]
  end

  def oauth_feature
    :oidc
  end

  def verify_response_body(data, oauth_token, secret, algorithm)
    assert data["refresh_token"] == oauth_token[:refresh_token]

    assert !data["expires_in"].nil?
    assert data["token_type"] == "bearer"

    payload, headers = JWT.decode(data["access_token"], secret, true, algorithms: [algorithm])

    assert headers["alg"] == algorithm
    assert payload["iss"] == "Example"
    assert payload["sub"] == account[:id]

    # TODO: verify id_token
  end
end
