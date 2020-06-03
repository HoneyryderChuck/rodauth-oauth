# frozen_string_literal: true

require "jwt"
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
end
