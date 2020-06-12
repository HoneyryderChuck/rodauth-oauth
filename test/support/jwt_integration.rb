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

  def set_authorization_header(token = oauth_token)
    id = token[:token]
    nonce = SecureRandom.alphanumeric(8)
    # The nonce value MUST consist of the age of the MAC credentials expressed as the number of seconds since
    # the credentials were issued to the client, a colon character (%x25), and a unique string (typically random).
    # The age value MUST be a positive integer and MUST NOT include leading zeros (e.g. "000137131200")
    nonce = "#{Time.now.to_i - token[:expires_in].to_i}:#{nonce}"
    signature = generate_mac_signature(token, nonce)

    header "Authorization", "MAC id=\"#{id}\", nonce=\"#{nonce}\", mac=\"#{signature}\""
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

  def verify_response_body(data, oauth_token, secret, algorithm)
    assert data["refresh_token"] == oauth_token[:refresh_token]

    assert !data["expires_in"].nil?
    assert data["token_type"] == "bearer"

    payload, headers = JWT.decode(data["access_token"], secret, true, algorithms: [algorithm])

    assert headers["alg"] == algorithm
    assert payload["iss"] == "Example"
    assert payload["sub"] == account[:id]
  end
end
