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
    assert json_body["issuer"] == "http://example.org"
    assert json_body["authorization_endpoint"] == "http://example.org/authorize"
    assert json_body["token_endpoint"] == "http://example.org/token"
    assert json_body["scopes_supported"] == %w[read write]
    assert json_body["response_types_supported"] == %w[code]
    assert json_body["response_modes_supported"] == %w[query form_post]
    assert json_body["grant_types_supported"] == %w[refresh_token authorization_code]
    assert json_body["token_endpoint_auth_methods_supported"] == %w[client_secret_basic client_secret_post]
  end

  def test_oauth_server_metadata_with_dynamic_registration
    rodauth do
      oauth_application_scopes %w[read write]
    end
    setup_application(:oauth_dynamic_client_registration)
    get("/.well-known/oauth-authorization-server")

    assert last_response.status == 200
    assert json_body["registration_endpoint"] == "http://example.org/register"
  end

  def test_oauth_server_metadata_with_token_revocation
    rodauth do
      oauth_application_scopes %w[read write]
    end
    setup_application(:oauth_token_revocation)
    get("/.well-known/oauth-authorization-server")

    assert last_response.status == 200
    assert json_body["revocation_endpoint"] == "http://example.org/revoke"
  end

  def test_oauth_server_metadata_with_token_introspection
    rodauth do
      oauth_application_scopes %w[read write]
    end
    setup_application(:oauth_token_introspection)
    get("/.well-known/oauth-authorization-server")

    assert last_response.status == 200
    assert json_body["introspection_endpoint"] == "http://example.org/introspect"
  end

  def test_oauth_server_metadata_with_pkce
    rodauth do
      oauth_application_scopes %w[read write]
    end
    setup_application(:oauth_pkce)
    get("/.well-known/oauth-authorization-server")

    assert last_response.status == 200
    assert json_body["code_challenge_methods_supported"] == "S256"
  end

  def test_oauth_server_metadata_with_implicit_grant
    rodauth do
      oauth_application_scopes %w[read write]
    end
    setup_application(:oauth_implicit_grant)
    get("/.well-known/oauth-authorization-server")

    assert last_response.status == 200
    assert json_body["scopes_supported"] == %w[read write]
    assert json_body["response_types_supported"] == %w[code token]
    assert json_body["response_modes_supported"] == %w[query form_post fragment]
    assert json_body["grant_types_supported"] == %w[refresh_token authorization_code implicit]
  end

  def test_oauth_server_metadata_with_device_code_grant
    setup_application(:oauth_device_code_grant)
    get("/.well-known/oauth-authorization-server")

    assert last_response.status == 200
    assert json_body["grant_types_supported"] == %w[refresh_token authorization_code urn:ietf:params:oauth:grant-type:device_code]
    assert json_body["device_authorization_endpoint"] == "http://example.org/device-authorization"
  end

  def test_oauth_server_metadata_with_route_prefix
    rodauth do
      prefix "/auth"
      oauth_application_scopes %w[read write]
    end
    setup_application(
      :oauth_dynamic_client_registration,
      :oauth_token_revocation,
      :oauth_token_introspection
    )
    get("/.well-known/oauth-authorization-server")

    assert last_response.status == 200
    assert json_body["issuer"] == "http://example.org"
    assert json_body["authorization_endpoint"] == "http://example.org/auth/authorize"
    assert json_body["token_endpoint"] == "http://example.org/auth/token"
    assert json_body["registration_endpoint"] == "http://example.org/auth/register"
    assert json_body["revocation_endpoint"] == "http://example.org/auth/revoke"
    assert json_body["introspection_endpoint"] == "http://example.org/auth/introspect"
  end

  private

  def setup_application(*args)
    super(*args, &:oauth_server_metadata)
  end
end
