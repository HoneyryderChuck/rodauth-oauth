# frozen_string_literal: true

require "test_helper"

class RodauthOauthServerMetadataTest < RodaIntegration
  include Rack::Test::Methods

  def test_oauth_server_metadata
    rodauth do
      oauth_application_scopes %w[read write]
    end
    setup_application
    get("/.well-known/oauth-authorization-server")

    assert last_response.status == 200
    assert json_body["issuer"] == "http://example.org/"
    assert json_body["authorization_endpoint"] == "http://example.org/oauth-authorize"
    assert json_body["token_endpoint"] == "http://example.org/oauth-token"
    assert json_body["registration_endpoint"] == "http://example.org/oauth-applications"
    assert json_body["scopes_supported"] == %w[read write]
    assert json_body["response_types_supported"] == %w[code]
    assert json_body["response_modes_supported"] == %w[query]
    assert json_body["grant_types_supported"] == %w[authorization_code]
    assert json_body["token_endpoint_auth_methods_supported"] == %w[client_secret_basic client_secret_post]
    assert json_body["revocation_endpoint"] == "http://example.org/oauth-revoke"
    assert json_body["introspection_endpoint"] == "http://example.org/oauth-introspect"
    assert json_body["code_challenge_methods_supported"] == "S256"
  end

  private

  def setup_application
    super(&:oauth_server_metadata)
  end
end
