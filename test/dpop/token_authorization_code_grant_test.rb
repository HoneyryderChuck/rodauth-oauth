# frozen_string_literal: true

require "test_helper"
require "webmock/minitest"

class RodauthOAuthDpopTokenAuthorizationCodeTest < DPoPIntegration
  include Rack::Test::Methods

  def test_dpop_jwt_header_invalid_typ
    ecdsa_key = OpenSSL::PKey::EC.generate("prime256v1")
    ecdsa_key.generate_key
    rodauth { oauth_jwt_keys("ES256" => ecdsa_key) }
    setup_application

    dpop_with_invalid_typ = generate_dpop_proof(ecdsa_key, typ: "invalid")
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
    ecdsa_key = OpenSSL::PKey::EC.generate("prime256v1")
    ecdsa_key.generate_key
    rodauth { oauth_jwt_keys("ES256" => ecdsa_key) }
    setup_application

    dpop_with_invalid_alg = generate_dpop_proof(ecdsa_key, alg: "none")
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
    ecdsa_key = OpenSSL::PKey::EC.generate("prime256v1")
    ecdsa_key.generate_key
    rodauth { oauth_jwt_keys("ES256" => ecdsa_key) }
    setup_application

    # Construct DPoP proof with an invalid JWK
    header "DPoP", generate_dpop_proof(ecdsa_key, private_jwk: true)
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
    ecdsa_key = OpenSSL::PKey::EC.generate("prime256v1")
    ecdsa_key.generate_key
    rodauth { oauth_jwt_keys("ES256" => ecdsa_key) }
    setup_application

    # Construct DPoP proof with an incorrect signature
    header "DPoP", generate_dpop_proof(ecdsa_key, bad_signature: true)
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
    ecdsa_key = OpenSSL::PKey::EC.generate("prime256v1")
    ecdsa_key.generate_key
    rodauth { oauth_jwt_keys("ES256" => ecdsa_key) }
    setup_application

    # Construct DPoP proof with incorrect htm
    header "DPoP", generate_dpop_proof(ecdsa_key, htm: "GET")
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
    ecdsa_key = OpenSSL::PKey::EC.generate("prime256v1")
    ecdsa_key.generate_key
    rodauth { oauth_jwt_keys("ES256" => ecdsa_key) }
    setup_application

    # Construct DPoP proof with incorrect htu
    header "DPoP", generate_dpop_proof(ecdsa_key, htu: "http://example.org/wrong")
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
    ecdsa_key = OpenSSL::PKey::EC.generate("prime256v1")
    ecdsa_key.generate_key
    rodauth do
      oauth_jwt_keys("ES256" => ecdsa_key)
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
    ecdsa_key = OpenSSL::PKey::EC.generate("prime256v1")
    ecdsa_key.generate_key
    rodauth { oauth_jwt_keys("ES256" => ecdsa_key) }
    setup_application

    # Make a request with DPoP headers to generate an access token
    header "DPoP", generate_dpop_proof(ecdsa_key)
    post(
      "/token",
      client_id: oauth_application[:client_id],
      client_secret: "CLIENT_SECRET",
      grant_type: "authorization_code",
      code: oauth_grant[:code],
      redirect_uri: oauth_grant[:redirect_uri]
    )

    assert_equal 200, last_response.status
    refute_nil json_body["access_token"]
  end

  def test_dpop_token_generation_with_nonce
    ecdsa_key = OpenSSL::PKey::EC.generate("prime256v1")
    ecdsa_key.generate_key
    rodauth do
      oauth_dpop_use_nonce true
      oauth_jwt_keys("ES256" => ecdsa_key)
    end
    setup_application

    # Make a request with DPoP headers to generate an access token
    header "DPoP", generate_dpop_proof(ecdsa_key)
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
    header "DPoP", generate_dpop_proof(ecdsa_key, nonce: nonce)
    post(
      "/token",
      client_id: oauth_application[:client_id],
      client_secret: "CLIENT_SECRET",
      grant_type: "authorization_code",
      code: oauth_grant[:code],
      redirect_uri: oauth_grant[:redirect_uri]
    )

    assert last_response.status == 200
    refute_nil json_body["access_token"]
  end
end
