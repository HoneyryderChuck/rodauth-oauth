# frozen_string_literal: true

require_relative File.join(__dir__, "jwt_integration")

class DPoPIntegration < JWTIntegration
  private

  def oauth_feature
    %i[oauth_authorization_code_grant oauth_dpop]
  end

  def setup_application(*)
    signing_key = OpenSSL::PKey::RSA.generate(2048)
    rodauth do
      oauth_jwt_keys("RS256" => signing_key)
    end
    @signing_key = signing_key
    super
    header "Accept", "application/json"
  end

  def generate_dpop_proof(
    key,
    public_key: key.public_key,
    access_token: nil,
    nonce: nil,
    aud: "http://example.org",
    typ: "dpop+jwt",
    alg: "RS256",
    private_jwk: false,
    bad_signature: false,
    request_method: "POST",
    request_uri: "#{aud}/token",
    htm: request_method,
    htu: request_uri
  )
    iat = Time.now.to_i

    input_string = "#{request_method}:#{request_uri}:#{iat}"
    jti = Digest::SHA256.hexdigest(input_string)
    # Generate key pair

    # DPoP JWT Header
    jwk = JWT::JWK.new(public_key)
    header = {
      typ: typ,
      alg: alg,
      jwk: jwk.export(include_private: private_jwk)
    }

    # DPoP JWT Payload
    payload = {
      jti: jti, # Unique token identifier
      htm: htm, # HTTP method of the request to which the DPoP token is attached, in uppercase. Adjust accordingly.
      htu: htu, # HTTP URL of the request, adjust if different
      iat: iat # Issued at
    }

    payload[:nonce] = nonce if nonce
    payload[:ath] = Base64.urlsafe_encode64(Digest::SHA256.digest(access_token), padding: false) if access_token

    key = OpenSSL::PKey::RSA.generate(2048) if bad_signature

    JWT.encode(payload, key, alg, header)
  end

  def generate_thumbprint(key, include_private: false)
    jwk = JWT::JWK.new(key)
    jwk = JWT::JWK.import(jwk.export(include_private: include_private))
    JWT::JWK::Thumbprint.new(jwk).generate
  end

  def verify_access_token(data, oauth_grant, bound_dpop_key:, signing_key: @signing_key, signing_algo: "RS256")
    claims = super(data, oauth_grant, signing_key: signing_key, signing_algo: signing_algo)

    assert claims.key?("cnf")
    assert claims["cnf"]["jkt"] == generate_thumbprint(bound_dpop_key)
  end
end
