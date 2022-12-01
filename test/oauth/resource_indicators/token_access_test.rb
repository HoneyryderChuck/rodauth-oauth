# frozen_string_literal: true

require "test_helper"

class RodauthOAuthResourceIndicatorsTokenAccessTest < RodaIntegration
  include Rack::Test::Methods

  def test_token_access_private_invalid_resource
    rodauth do
      oauth_application_scopes %w[read write]
    end
    setup_application

    header "Accept", "application/json"
    set_authorization_header(oauth_grant_with_token(resource: "http://smthelse.com"))
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_valid_token
    rodauth do
      oauth_application_scopes %w[read write]
    end
    setup_application

    header "Accept", "application/json"
    set_authorization_header(oauth_grant_with_token(resource: "http://example.org"))
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  private

  def oauth_feature
    :oauth_resource_indicators
  end
end
