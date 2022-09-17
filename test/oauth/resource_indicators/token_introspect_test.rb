# frozen_string_literal: true

require "test_helper"

class RodauthOAuthResourceIndicatorsTokenIntrospectTest < RodaIntegration
  include Rack::Test::Methods

  def test_oauth_introspect_access_token
    rodauth do
      oauth_application_scopes %w[read write]
    end

    setup_application
    oauth_token = set_oauth_token(resource: "https://example.org")
    login

    header "Accept", "application/json"

    # valid token, and now we're getting somewhere
    post("/introspect", {
           token: oauth_token[:token]
         })
    assert last_response.status == 200
    assert json_body["active"] == true
    assert json_body["scope"] == oauth_token[:scopes]
    assert json_body["scope"] == oauth_token[:scopes]
    assert json_body["client_id"] == oauth_application[:client_id]
    assert json_body["token_type"] == "bearer"
    assert json_body["aud"] == %w[https://example.org]
    assert json_body.key?("exp")
  end

  private

  def oauth_feature
    %i[oauth_token_introspection oauth_resource_indicators]
  end

  # overriding to implement the client/secret basic authorization
  def login
    header "Authorization", "Basic #{authorization_header(
      username: oauth_application[:client_id],
      password: 'CLIENT_SECRET'
    )}"
  end
end
