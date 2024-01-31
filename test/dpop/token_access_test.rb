# frozen_string_literal: true

require "test_helper"

class RodauthOAuthDpopTokenAccessTest < DPoPIntegration
  include Rack::Test::Methods

  def test_dpop_access_protected_resource_without_dpop_token
    rodauth do
      oauth_dpop_bound_access_tokens true
    end
    setup_application

    get("/private")

    assert last_response.status == 401
    assert last_response.headers["WWW-Authenticate"].start_with?("DPoP algs=\"RS256 ")
    assert json_body["error"] == "invalid_client"
  end

  def test_dpop_access_protected_resource_with_dpop_token_as_bearer
    dpop_key = OpenSSL::PKey::RSA.generate(2048)
    dpop_public_key = dpop_key.public_key
    setup_application

    header "DPoP", generate_dpop_proof(dpop_key, public_key: dpop_public_key)
    post(
      "/token",
      client_id: oauth_application[:client_id],
      client_secret: "CLIENT_SECRET",
      grant_type: "authorization_code",
      code: oauth_grant[:code],
      redirect_uri: oauth_grant[:redirect_uri]
    )
    assert last_response.status == 200
    access_token = json_body["access_token"]

    verify_access_token(access_token, oauth_grant, bound_dpop_key: dpop_public_key)

    # Access the protected resource with the token
    header "DPoP",
           generate_dpop_proof(dpop_key, request_method: "GET", request_uri: "http://example.org/private", access_token: access_token)
    header "Authorization", "Bearer #{access_token}"

    get("/private")

    assert_equal 401, last_response.status
  end

  def test_dpop_access_protected_resource_with_dpop_token_and_bearer
    dpop_key = OpenSSL::PKey::RSA.generate(2048)
    dpop_public_key = dpop_key.public_key
    setup_application

    header "DPoP", generate_dpop_proof(dpop_key, public_key: dpop_public_key)
    post(
      "/token",
      client_id: oauth_application[:client_id],
      client_secret: "CLIENT_SECRET",
      grant_type: "authorization_code",
      code: oauth_grant[:code],
      redirect_uri: oauth_grant[:redirect_uri]
    )
    assert last_response.status == 200
    access_token = json_body["access_token"]
    verify_access_token(access_token, oauth_grant, bound_dpop_key: dpop_public_key)

    # Access the protected resource with the token
    header "DPoP",
           generate_dpop_proof(dpop_key, public_key: dpop_public_key, request_method: "GET", request_uri: "http://example.org/private",
                                         access_token: access_token)
    header "Authorization", "DPoP #{access_token}"
    header "Authorization", "Bearer TOKEN"

    get("/private")

    assert_equal 401, last_response.status
  end

  def test_dpop_access_protected_resource_with_dpop_token
    dpop_key = OpenSSL::PKey::RSA.generate(2048)
    dpop_public_key = dpop_key.public_key
    rodauth do
      oauth_dpop_bound_access_tokens true
    end
    setup_application

    header "DPoP", generate_dpop_proof(dpop_key, public_key: dpop_public_key)
    post(
      "/token",
      client_id: oauth_application[:client_id],
      client_secret: "CLIENT_SECRET",
      grant_type: "authorization_code",
      code: oauth_grant[:code],
      redirect_uri: oauth_grant[:redirect_uri]
    )
    assert last_response.status == 200
    access_token = json_body["access_token"]
    verify_access_token(access_token, oauth_grant, bound_dpop_key: dpop_public_key)

    # Access the protected resource with the token
    header "DPoP",
           generate_dpop_proof(dpop_key, request_method: "GET", request_uri: "http://example.org/private", access_token: access_token)
    header "Authorization", "DPoP #{access_token}"

    get("/private")

    assert_equal 200, last_response.status
  end
end
