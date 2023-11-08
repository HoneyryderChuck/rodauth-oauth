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

  def oauth_grant_with_token(params = {})
    super({ scopes: "openid" }.merge(params))
  end

  def test_scopes
    %w[openid]
  end

  def oauth_feature
    :oidc
  end

  def verify_access_token_response(data, oauth_grant, secret, algorithm)
    super
    assert data.key?("id_token")
    verify_id_token(data["id_token"], oauth_grant, signing_key: secret, signing_algo: algorithm)
  end

  def verify_id_token(data, oauth_grant, signing_key:, signing_algo: "RS256", decryption_key: nil)
    claims, = verify_jwt_token(data, signing_key, signing_algo, decryption_key: decryption_key)
    verify_id_token_claims(claims, oauth_grant) if oauth_grant
    yield claims if block_given?
    claims
  end

  def verify_id_token_claims(claims, oauth_grant)
    verify_access_token_claims(claims, oauth_grant)

    assert claims["nonce"] == oauth_grant[:nonce]
    assert claims.key?("auth_time")
  end

  def verify_logout_token(data, oauth_grant, signing_key:, signing_algo: "RS256", decryption_key: nil)
    claims, headers = verify_jwt_token(data, signing_key, signing_algo, decryption_key: decryption_key)
    verify_id_token_claims(claims, oauth_grant) if oauth_grant
    assert headers["typ"] == "logout+jwt"
    assert claims["events"].is_a?(Hash)
    assert claims["events"].key?("http://schemas.openid.net/event/backchannel-logout")
    yield claims if block_given?
    claims
  end
end
