# frozen_string_literal: true

require "test_helper"

class RodauthOauthJwtServerMetadataTest < JWTIntegration
  include Rack::Test::Methods

  def test_oauth_jwt_server_metadata
    jws_rs256_key = OpenSSL::PKey::RSA.generate(2048)
    jws_rs512_key = OpenSSL::PKey::RSA.generate(2048)
    rodauth do
      oauth_jwt_keys { { "RS256" => jws_rs256_key, "RS512" => jws_rs512_key } }
      oauth_jwt_algorithm "RS256"
    end
    setup_application
    get("/.well-known/oauth-authorization-server")

    assert last_response.status == 200
    assert json_body["token_endpoint_auth_signing_alg_values_supported"] == %w[RS256 RS512]
    assert json_body["jwks_uri"] == "http://example.org/jwks"
  end

  private

  def setup_application
    super(&:oauth_server_metadata)
  end
end
