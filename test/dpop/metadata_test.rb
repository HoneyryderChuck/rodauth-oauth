# frozen_string_literal: true

require "test_helper"

class RodauthOauthDPoPServerMetadataTest < JWTIntegration
  include Rack::Test::Methods

  def test_oauth_dpop_signing_alg_values_supported
    rodauth do
      oauth_dpop_signing_alg_values_supported %w[ES256]
    end

    setup_application(:oauth_dpop, :oauth_authorization_code_grant,
                      &:load_oauth_server_metadata_route)

    get("/.well-known/oauth-authorization-server")

    assert last_response.status == 200

    assert json_body["dpop_signing_alg_values_supported"] == %w[ES256]
  end
end
