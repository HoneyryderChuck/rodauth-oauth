# frozen_string_literal: true

require "test_helper"
require "webmock/minitest"

class RodauthOAuthDpopTokenAuthorizationCodeTest < DPoPIntegration
  include Rack::Test::Methods

  def test_dpop_jwt_header_invalid_typ
    dpop_key = OpenSSL::PKey::RSA.generate(2048)
    setup_application

    dpop_with_invalid_typ = generate_dpop_proof(dpop_key, typ: "invalid")
    header "DPoP", dpop_with_invalid_typ
    post(
      "/token",
      client_id: oauth_application[:client_id],
      client_secret: "CLIENT_SECRET",
      grant_type: "authorization_code",
      code: oauth_grant[:code],
      redirect_uri: oauth_grant[:redirect_uri]
    )

    verify_response(400)
    assert json_body["error"] == "invalid_dpop_proof"
    assert json_body["error_description"] == "Invalid DPoP proof"
  end

  def test_dpop_jwt_header_invalid_alg
    dpop_key = OpenSSL::PKey::RSA.generate(2048)
    setup_application

    dpop_with_invalid_alg = generate_dpop_proof(dpop_key, alg: "none")
    header "DPoP", dpop_with_invalid_alg
    post(
      "/token",
      client_id: oauth_application[:client_id],
      client_secret: "CLIENT_SECRET",
      grant_type: "authorization_code",
      code: oauth_grant[:code],
      redirect_uri: oauth_grant[:redirect_uri]
    )

    verify_response(400)
    assert json_body["error"] == "invalid_dpop_proof"
    assert json_body["error_description"] == "Invalid DPoP proof"
  end

  # JWK Validation Test
  def test_dpop_private_jwk
    dpop_key = OpenSSL::PKey::RSA.generate(2048)
    setup_application

    # Construct DPoP proof with an invalid JWK
    header "DPoP", generate_dpop_proof(dpop_key, public_key: dpop_key, private_jwk: true)
    post(
      "/token",
      client_id: oauth_application[:client_id],
      client_secret: "CLIENT_SECRET",
      grant_type: "authorization_code",
      code: oauth_grant[:code],
      redirect_uri: oauth_grant[:redirect_uri]
    )

    verify_response(400)
    assert json_body["error"] == "invalid_dpop_proof"
    assert json_body["error_description"] == "Invalid DPoP proof"
  end

  # JWT Signature Validation Test
  def test_dpop_jwt_invalid_signature
    dpop_key = OpenSSL::PKey::RSA.generate(2048)
    setup_application

    # Construct DPoP proof with an incorrect signature
    header "DPoP", generate_dpop_proof(dpop_key, bad_signature: true)
    post(
      "/token",
      client_id: oauth_application[:client_id],
      client_secret: "CLIENT_SECRET",
      grant_type: "authorization_code",
      code: oauth_grant[:code],
      redirect_uri: oauth_grant[:redirect_uri]
    )

    verify_response(400)
    assert json_body["error"] == "invalid_dpop_proof"
    assert json_body["error_description"] == "Invalid DPoP proof"
  end

  # HTM and HTU Claims Validation Test
  def test_dpop_jwt_invalid_htm
    dpop_key = OpenSSL::PKey::RSA.generate(2048)
    setup_application

    # Construct DPoP proof with incorrect htm
    header "DPoP", generate_dpop_proof(dpop_key, htm: "GET")
    post(
      "/token",
      client_id: oauth_application[:client_id],
      client_secret: "CLIENT_SECRET",
      grant_type: "authorization_code",
      code: oauth_grant[:code],
      redirect_uri: oauth_grant[:redirect_uri]
    )

    verify_response(400)
    assert json_body["error"] == "invalid_dpop_proof"
    assert json_body["error_description"] == "Invalid DPoP htm"
  end

  def test_dpop_jwt_invalid_htu
    dpop_key = OpenSSL::PKey::RSA.generate(2048)
    setup_application

    # Construct DPoP proof with incorrect htu
    header "DPoP", generate_dpop_proof(dpop_key, htu: "http://example.org/wrong")
    post(
      "/token",
      client_id: oauth_application[:client_id],
      client_secret: "CLIENT_SECRET",
      grant_type: "authorization_code",
      code: oauth_grant[:code],
      redirect_uri: oauth_grant[:redirect_uri]
    )

    verify_response(400)
    assert json_body["error"] == "invalid_dpop_proof"
    assert json_body["error_description"] == "Invalid DPoP htu"
  end

  def test_fail_generation_without_dpop_when_dpop_bound_is_true
    # dpop_key = OpenSSL::PKey::RSA.generate(2048)
    rodauth do
      oauth_dpop_bound_access_tokens true
    end
    setup_application

    header "Authorization", "Basic #{authorization_header(
      username: oauth_application[:client_id],
      password: 'CLIENT_SECRET'
    )}"

    post(
      "/token",
      client_id: oauth_application[:client_id],
      client_secret: "CLIENT_SECRET",
      grant_type: "authorization_code",
      code: oauth_grant[:code],
      redirect_uri: oauth_grant[:redirect_uri]
    )

    assert last_response.status == 401
    assert last_response.headers["WWW-Authenticate"].include?("DPoP")
    assert last_response.headers["WWW-Authenticate"].include?("algs=\"RS256 ")
    assert json_body["error"] == "invalid_client"
  end

  def test_dpop_access_token_generation_with_dpop_proof
    dpop_key = OpenSSL::PKey::RSA.generate(2048)
    dpop_public_key = dpop_key.public_key
    setup_application

    header "DPoP", generate_dpop_proof(dpop_key, public_key: dpop_public_key)

    # Make a request with DPoP headers to generate an access token
    header "DPoP", generate_dpop_proof(dpop_key)
    post(
      "/token",
      client_id: oauth_application[:client_id],
      client_secret: "CLIENT_SECRET",
      grant_type: "authorization_code",
      code: oauth_grant[:code],
      redirect_uri: oauth_grant[:redirect_uri]
    )

    assert_equal 200, last_response.status
    verify_access_token(json_body["access_token"], oauth_grant, bound_dpop_key: dpop_public_key)
  end

  def test_dpop_token_generation_with_nonce
    dpop_key = OpenSSL::PKey::RSA.generate(2048)
    rodauth do
      oauth_dpop_use_nonce true
    end
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

    verify_response(400)
    assert json_body["error"] == "use_dpop_nonce"
    assert last_response.headers.key?("DPoP-Nonce")

    nonce = last_response.headers["DPop-Nonce"]
    @json_body = nil

    # Make a request with DPoP headers to generate an access token
    header "DPoP", generate_dpop_proof(dpop_key, nonce: nonce)
    post(
      "/token",
      client_id: oauth_application[:client_id],
      client_secret: "CLIENT_SECRET",
      grant_type: "authorization_code",
      code: oauth_grant[:code],
      redirect_uri: oauth_grant[:redirect_uri]
    )

    assert last_response.status == 200
    verify_access_token(json_body["access_token"], oauth_grant, bound_dpop_key: dpop_public_key)
  end
end
