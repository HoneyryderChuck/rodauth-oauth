# frozen_string_literal: true

require "test_helper"

class RodauthOAuthResourceIndicatorsTokenAuthorizationCodeTest < RodaIntegration
  include Rack::Test::Methods

  def test_token_authorization_code_unsupported_unsupported_resource
    rodauth do
      oauth_application_scopes %w[read write]
    end
    setup_application
    oauth_grant = set_oauth_grant(resource: "https://example.org")
    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         resource: "https://smthelse.com",
         redirect_uri: oauth_grant[:redirect_uri])

    assert last_response.status == 400
    assert json_body["error"] == "invalid_target"
  end

  def test_token_authorization_code_exact
    rodauth do
      oauth_application_scopes %w[read write]
    end
    setup_application
    oauth_grant = set_oauth_grant(resource: "https://example.org")

    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         resource: "https://example.org",
         redirect_uri: oauth_grant[:redirect_uri])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_tokens].count == 1

    oauth_token = db[:oauth_tokens].first

    verify_oauth_grant_revoked(oauth_token)
    verify_access_token_response(json_body, oauth_token)
    assert oauth_token[:resource] == "https://example.org"
  end

  def test_token_authorization_code_one_of
    rodauth do
      oauth_application_scopes %w[read write]
    end
    setup_application
    oauth_grant = set_oauth_grant(resource: "https://example.org https://example2.org")

    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         resource: "https://example.org",
         redirect_uri: oauth_grant[:redirect_uri])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_tokens].count == 1

    oauth_token = db[:oauth_tokens].first

    verify_oauth_grant_revoked(oauth_token)
    verify_access_token_response(json_body, oauth_token)
    assert oauth_token[:resource] == "https://example.org"
  end

  private

  def oauth_feature
    %i[oauth_authorization_code_grant oauth_resource_indicators]
  end

  def setup_application
    super
    header "Accept", "application/json"
  end
end
