# frozen_string_literal: true

require "test_helper"

class RodauthSamlerverMetadataTest < RodaIntegration
  include Rack::Test::Methods

  def test_saml_server_metadata
    rodauth do
      oauth_application_scopes %w[read write]
    end
    setup_application(:oauth_saml_bearer_grant)
    get("/.well-known/oauth-authorization-server")

    assert last_response.status == 200
    assert json_body["issuer"] == "http://example.org"
    assert json_body["authorization_endpoint"] == "http://example.org/authorize"
    assert json_body["token_endpoint"] == "http://example.org/token"
    assert json_body["scopes_supported"] == %w[read write]
    assert json_body["token_endpoint_auth_methods_supported"] == %w[client_secret_basic client_secret_post
                                                                    urn:ietf:params:oauth:client-assertion-type:saml2-bearer]
  end

  private

  def setup_application(*args, **kwargs)
    super(*args, **kwargs, &:load_oauth_server_metadata_route)
  end
end
