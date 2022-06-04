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
    verify_id_token(data["id_token"], oauth_token, signing_key: secret, signing_algo: algorithm)
  end

  def verify_id_token(data, oauth_token, signing_key:, signing_algo: "RS256", decryption_key: nil)
    data = JWE.decrypt(data, decryption_key) if decryption_key
    claims, headers = JWT.decode(data, signing_key, true, { "algorithm" => signing_algo })

    assert headers["alg"] == signing_algo
    verify_id_token_claims(claims, oauth_token)
    yield claims if block_given?
  end

  def verify_id_token_claims(claims, oauth_token)
    verify_jwt_claims(claims, oauth_token)

    assert claims["nonce"] == oauth_token[:nonce]
  end
end
