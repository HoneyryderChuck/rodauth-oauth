# frozen_string_literal: true

require "test_helper"

class RodauthOauthJwtServerMetadataTest < JWTIntegration
  include Rack::Test::Methods

  def test_oauth_jwt_server_metadata
    rodauth do
      oauth_jwt_algorithm "HS256"
    end
    setup_application
    get("/.well-known/oauth-authorization-server")

    assert last_response.status == 200
    assert json_body["token_endpoint_auth_signing_alg_values_supported"] == %w[HS256]
    assert json_body["jwks_uri"] == "http://example.org/oauth-jwks"
  end

  private

  def setup_application
    super(&:oauth_server_metadata)
  end
end
