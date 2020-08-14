# frozen_string_literal: true

require "test_helper"

class RodauthOAuthTokenSAMLAuthorizationCodeTest < SAMLIntegration
  include Rack::Test::Methods

  def test_token_authorization_assertion_no_params
    setup_application
    login

    post("/token")
    assert last_response.status == 401
    assert json_body["error"] == "invalid_client"
  end

  def test_token_authorization_assertion_no_grant_type
    setup_application
    login
    post("/token", assertion: saml_assertion)

    assert last_response.status == 401
    assert json_body["error"] == "invalid_client"
  end

  def test_token_authorization_assertion_unsupported_grant_type
    setup_application
    login
    post("/token",
         grant_type: "smthsmth",
         assertion: saml_assertion)

    assert last_response.status == 401
    assert json_body["error"] == "invalid_client"
  end

  def test_token_authorization_assertion_gibberish
    skip
  end

  def test_token_authorization_assertion_successful
    setup_application
    login

    post("/token",
         grant_type: "http://oauth.net/grant_type/assertion/saml/2.0/bearer",
         assertion: saml_assertion)

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_tokens].count == 1

    access_token = db[:oauth_tokens].first

    assert access_token[:scopes] == oauth_application[:scopes]
    assert json_body["token_type"] == "bearer"
    assert json_body["access_token"] == access_token[:token]

    assert json_body["refresh_token"] == access_token[:refresh_token]
    assert !json_body["expires_in"].nil?
  end

  private

  def setup_application
    super
    header "Accept", "application/json"
  end

  def saml_assertion
    page.body
  end
end
