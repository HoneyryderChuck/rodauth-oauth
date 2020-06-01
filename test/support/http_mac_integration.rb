# frozen_string_literal: true

require_relative File.join(__dir__, "roda_integration")

class HTTPMacIntegration < RodaIntegration
  private

  def oauth_feature
    :oauth_http_mac
  end

  def oauth_token(params = {})
    @oauth_token ||= begin
      id = db[:http_mac_oauth_tokens].insert({
        account_id: account[:id],
        oauth_application_id: oauth_application[:id],
        oauth_grant_id: oauth_grant[:id],
        refresh_token: "REFRESH_TOKEN",
        token: "MAC_KEY_ID",
        mac_key: "MAC_KEY",
        expires_in: Time.now + 60 * 5,
        scopes: oauth_grant[:scopes]
      }.merge(params))
      db[:http_mac_oauth_tokens].filter(id: id).first
    end
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

  def generate_mac_signature(token, nonce)
    request_signature = [
      nonce,
      "GET",
      "/private",
      "example.org",
      80
    ].join("\n") + ("\n" * 3)

    Base64.strict_encode64 \
      OpenSSL::HMAC.digest(OpenSSL::Digest.new("SHA256").new, token[:mac_key], request_signature)
  end

  def setup_application
    rodauth do
      oauth_tokens_table :http_mac_oauth_tokens
    end
    super
  end
end
