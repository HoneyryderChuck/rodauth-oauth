# frozen_string_literal: true

require "test_helper"

# oauth_pkce lets clients without credentials redeem authorization codes by presenting a code_verifier.
# These tests check that this relaxation stays within the authorization code grant, and that applications
# which registered a confidential token_endpoint_auth_method still have to authenticate.
class RodauthOAuthPkceTokenClientAuthenticationTest < RodaIntegration
  include Rack::Test::Methods

  def test_token_authorization_code_pkce_public_client_without_credentials
    setup_application(:oauth_pkce)
    public_application = oauth_application(token_endpoint_auth_method: "none")
    pkce_grant = oauth_grant(oauth_application: public_application,
                             code_challenge_method: "S256", code_challenge: PKCE_CHALLENGE)

    post("/token",
         client_id: public_application[:client_id],
         grant_type: "authorization_code",
         code: pkce_grant[:code],
         redirect_uri: pkce_grant[:redirect_uri],
         code_verifier: PKCE_VERIFIER)

    assert last_response.status == 200
    assert !json_body["access_token"].nil?
  end

  def test_token_authorization_code_pkce_client_with_registered_auth_method_without_credentials
    setup_application(:oauth_pkce)
    confidential_application = oauth_application(token_endpoint_auth_method: "client_secret_basic")
    pkce_grant = oauth_grant(oauth_application: confidential_application,
                             code_challenge_method: "S256", code_challenge: PKCE_CHALLENGE)

    post("/token",
         client_id: confidential_application[:client_id],
         grant_type: "authorization_code",
         code: pkce_grant[:code],
         redirect_uri: pkce_grant[:redirect_uri],
         code_verifier: PKCE_VERIFIER)

    assert last_response.status == 401
    assert json_body["error"] == "invalid_client"
  end

  def test_token_authorization_code_pkce_client_with_registered_auth_method_with_credentials
    setup_application(:oauth_pkce)
    confidential_application = oauth_application(token_endpoint_auth_method: "client_secret_basic")
    pkce_grant = oauth_grant(oauth_application: confidential_application,
                             code_challenge_method: "S256", code_challenge: PKCE_CHALLENGE)

    header "Authorization", "Basic #{authorization_header(username: confidential_application[:client_id], password: 'CLIENT_SECRET')}"
    post("/token",
         grant_type: "authorization_code",
         code: pkce_grant[:code],
         redirect_uri: pkce_grant[:redirect_uri],
         code_verifier: PKCE_VERIFIER)

    assert last_response.status == 200
  end

  def test_token_client_credentials_with_code_verifier_without_credentials
    setup_application(:oauth_pkce, :oauth_client_credentials_grant)
    confidential_application = oauth_application(token_endpoint_auth_method: "client_secret_basic")

    post("/token",
         client_id: confidential_application[:client_id],
         grant_type: "client_credentials",
         code_verifier: "")

    assert last_response.status == 401
    assert json_body["error"] == "invalid_client"
  end

  def test_token_client_credentials_with_code_verifier_without_registered_auth_method
    setup_application(:oauth_pkce, :oauth_client_credentials_grant)

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "client_credentials",
         code_verifier: "")

    assert last_response.status == 401
    assert json_body["error"] == "invalid_client"
  end

  def test_token_refresh_token_with_code_verifier_without_credentials
    setup_application(:oauth_pkce)
    confidential_application = oauth_application(token_endpoint_auth_method: "client_secret_basic")
    grant = oauth_grant_with_token(oauth_application: confidential_application)

    post("/token",
         client_id: confidential_application[:client_id],
         grant_type: "refresh_token",
         refresh_token: grant[:refresh_token],
         code_verifier: "x")

    assert last_response.status == 401
    assert json_body["error"] == "invalid_client"
  end

  def test_introspect_with_code_verifier_without_credentials
    setup_application(:oauth_pkce, :oauth_token_introspection)
    confidential_application = oauth_application(token_endpoint_auth_method: "client_secret_basic")
    grant = oauth_grant_with_token(oauth_application: confidential_application)

    header "Accept", "application/json"
    post("/introspect",
         client_id: confidential_application[:client_id],
         token: grant[:token],
         code_verifier: "x")

    assert last_response.status == 401
  end
end
