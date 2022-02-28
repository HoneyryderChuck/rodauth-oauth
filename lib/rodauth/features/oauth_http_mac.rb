# frozen-string-literal: true

require "rodauth/oauth/refinements"

module Rodauth
  Feature.define(:oauth_http_mac, :OauthHttpMac) do
    using PrefixExtensions

    depends :oauth

    auth_value_method :oauth_token_type, "mac"
    auth_value_method :oauth_mac_algorithm, "hmac-sha-256" # hmac-sha-256, hmac-sha-1
    auth_value_method :oauth_tokens_mac_key_column, :mac_key

    def authorization_token
      return @authorization_token if defined?(@authorization_token)

      @authorization_token = begin
        value = request.get_header("HTTP_AUTHORIZATION").to_s

        scheme, token = value.split(/ +/, 2)

        return unless scheme == "MAC"

        mac_attributes = parse_mac_authorization_header_props(token)

        oauth_token = oauth_token_by_token(mac_attributes["id"])

        return unless oauth_token && mac_signature_matches?(oauth_token, mac_attributes)

        oauth_token

        # TODO: set new MAC-KEY for the next request
      end
    end

    private

    def generate_oauth_token(params = {}, *args)
      super({ oauth_tokens_mac_key_column => oauth_unique_id_generator }.merge(params), *args)
    end

    def json_access_token_payload(oauth_token)
      payload = super

      payload["mac_key"] = oauth_token[oauth_tokens_mac_key_column]
      payload["mac_algorithm"] = oauth_mac_algorithm

      payload
    end

    def mac_signature_matches?(oauth_token, mac_attributes)
      nonce = mac_attributes["nonce"]
      uri = URI(request.url)

      request_signature = [
        nonce,
        request.request_method,
        uri.request_uri,
        uri.host,
        uri.port
      ].join("\n") + ("\n" * 3)

      mac_algorithm = case oauth_mac_algorithm
                      when "hmac-sha-256"
                        OpenSSL::Digest::SHA256
                      when "hmac-sha-1"
                        OpenSSL::Digest::SHA1
                      else
                        raise ArgumentError, "Unsupported algorithm"
                      end

      mac_signature = Base64.strict_encode64 \
        OpenSSL::HMAC.digest(mac_algorithm.new, oauth_token[oauth_tokens_mac_key_column], request_signature)

      mac_signature == mac_attributes["mac"]
    end

    def parse_mac_authorization_header_props(token)
      @mac_authorization_header_props = token.split(/ *, */).each_with_object({}) do |prop, props|
        field, value = prop.split(/ *= */, 2)
        props[field] = value.delete_prefix("\"").delete_suffix("\"")
      end
    end
  end
end
