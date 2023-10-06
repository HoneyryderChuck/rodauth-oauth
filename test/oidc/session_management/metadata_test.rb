# frozen_string_literal: true

require "test_helper"

class RodauthOauthOidcSessionManagementServerMetadataTest < OIDCIntegration
  include Rack::Test::Methods
  include TestSchemas::Methods

  def test_oidc_openid_configuration
    rsa_private = OpenSSL::PKey::RSA.generate(2048)
    rodauth do
      oauth_application_scopes %w[openid email]
      oauth_jwt_keys("RS256" => rsa_private)
    end
    setup_application
    get("/.well-known/openid-configuration")

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"
    assert json_body["issuer"] == "http://example.org"
    assert json_body["check_session_iframe"] == "http://example.org/check-session"
  end

  private

  def oauth_feature
    %i[oidc oidc_session_management]
  end

  def setup_application(*args)
    super(*args, &:load_openid_configuration_route)
  end
end
