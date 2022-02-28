# frozen_string_literal: true

require "test_helper"

class RodauthOAuthTokenSAMLAuthorizationCodeTest < SAMLIntegration
  include Rack::Test::Methods

  def test_token_grant_assertion_no_params
    setup_application

    post("/token")
    assert last_response.status == 401
    assert json_body["error"] == "invalid_client"
  end

  def test_token_grant_assertion_no_grant_type
    setup_application
    post("/token", assertion: saml_assertion(account))

    assert last_response.status == 401
    assert json_body["error"] == "invalid_client"
  end

  def test_token_grant_assertion_unsupported_grant_type
    setup_application
    post("/token",
         grant_type: "smthsmth",
         assertion: saml_assertion(account))

    assert last_response.status == 401
    assert json_body["error"] == "invalid_client"
  end

  def test_token_grant_assertion_successful
    setup_application

    post("/token",
         grant_type: "urn:ietf:params:oauth:grant-type:saml2-bearer",
         assertion: saml_assertion(account))

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

  def test_token_grant_client_authentication_with_assertion_successful
    setup_application

    post("/token",
         client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:saml2-bearer",
         client_assertion: saml_assertion(oauth_application),
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

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
end
