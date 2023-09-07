# frozen_string_literal: true

require "test_helper"
require "webmock/minitest"
# require_relative "../../../lib/rodauth/features/oauth_dpop"

class RodauthOAuthDPoPTest < JWTIntegration
  include Rack::Test::Methods
  def test_jwt_header_validation
    setup_application

    # Test for invalid 'typ' in DPoP proof
    dpop_with_invalid_typ = generate_dpop_proof(typ: "invalid")
    assert_token_request_fails(dpop_with_invalid_typ)

    # Test for invalid 'alg' in DPoP proof
    dpop_with_invalid_alg = generate_dpop_proof(alg: "none")
    assert_token_request_fails(dpop_with_invalid_alg)
  end

  # Assert the token request fails with the given dpop_token
  def assert_token_request_fails(dpop_token)
    header "DPoP", dpop_token
    post_token_request
    refute_equal 200,
                 last_response.status,
                 "Unexpected success with DPoP token: #{dpop_token}. Response: #{last_response.body}"
  end

  # JWK Validation Test
  def test_jwk_validation
    setup_application

    # Construct DPoP proof with an invalid JWK
    header "DPoP", generate_dpop_proof(invalid_jwk: true)
    post_token_request

    refute_equal 200, last_response.status
  end

  # JWT Signature Validation Test
  def test_jwt_signature_validation
    setup_application

    # Construct DPoP proof with an incorrect signature
    header "DPoP", generate_dpop_proof(bad_signature: true)
    post_token_request

    refute_equal 200, last_response.status
  end

  # HTM and HTU Claims Validation Test
  def test_htm_htu_claims_validation
    setup_application

    # Construct DPoP proof with incorrect htm
    header "DPoP", generate_dpop_proof(htm: "GET")
    post_token_request

    refute_equal 200, last_response.status

    # Construct DPoP proof with incorrect htu
    header "DPoP", generate_dpop_proof(htu: "http://example.org/wrong")
    post_token_request

    refute_equal 200, last_response.status
  end

  def test_access_token_generation_with_dpop_proof
    setup_application

    # Make a request with DPoP headers to generate an access token
    header "DPoP", generate_dpop_proof
    post_token_request

    assert_equal 200, last_response.status
    refute_nil json_body["access_token"]
  end

  def test_access_protected_resource_with_dpop_token
    rodauth { oauth_dpop_bound_access_tokens true }
    setup_application

    header "DPoP", generate_dpop_proof
    header "Authorization", authorization_basic_header
    post_token_request
    token = json_body["access_token"]

    # Access the protected resource with the token
    header "Authorization", "Bearer #{token}"

    get("/private")

    assert_equal 200, last_response.status
    # Additional assertions related to the response data can be added here
  end

  def test_fail_generation_without_dpop_when_dpop_bound_is_true
    rodauth { oauth_dpop_bound_access_tokens true }
    setup_application

    post_token_request

    assert last_response.status == 400 || last_response.status == 401

    assert json_body["error"]
  end

  def test_token_introspection_with_dpop_bound_token
    rodauth { oauth_dpop_bound_access_tokens true }
    setup_application(:oauth_token_introspection)

    header "DPoP", generate_dpop_proof
    header "Authorization", authorization_basic_header
    token = generate_access_token(oauth_grant(scopes: "openid"))

    verify_response

    # valid token, and now we're getting somewhere
    post(
      "/introspect",
      { token: json_body["access_token"], token_type_hint: "access_token" }
    )

    @json_body = nil
    verify_response

    assert_equal 200, last_response.status, "Expected a 200 OK status"
  end

  def test_token_introspection_without_dpop_bound_token
    rodauth { oauth_dpop_bound_access_tokens true }
    setup_application(:oauth_token_introspection)

    token = generate_access_token(oauth_grant(scopes: "openid"))

    post_introspect_request(token)

    refute_equal 200, last_response.status, "Expected a 200 OK status"
  end

  private

  def post_introspect_request(token)
    header "Authorization", authorization_basic_header
    post "/introspect",
         {
           token: token,
           token_type_hint: "access_token" # You can also test for "refresh_token" if needed
         }
  end

  private

  def setup_application(*)
    rodauth { oauth_jwt_keys("HS256" => "SECRET") }
    super
    header "Accept", "application/json"
  end

  def authorization_basic_header
    client_id = oauth_application[:client_id]
    header = Base64.strict_encode64("#{client_id}:CLIENT_SECRET")
    "Basic #{header}"
  end

  def oauth_feature
    %i[oauth_authorization_code_grant oauth_dpop]
  end

  def generate_access_token(grant)
    header "Authorization", authorization_basic_header
    # header "DPoP", generate_dpop_proof
    post_token_request

    json_body["access_token"]
  end

  def generate_refresh_token(grant)
    header "Authorization", authorization_basic_header
    header "DPoP", generate_dpop_proof
    post_token_request

    json_body["refresh_token"]
  end

  def login(_token)
    header "Authorization", authorization_basic_header
  end

  def generate_dpop_proof(
    iss = "http://example.org",
    typ = "dpop+jwt",
    alg = "ES256",
    remove_jwk = false,
    invalid_jwk = false,
    bad_signature = false,
    htm = "POST",
    htu = "#{iss}/token"
  )
    curve_name = "prime256v1"

    time_now = Time.now.to_i

    input_string = "#{iss}:#{time_now}"
    jti = Digest::SHA256.hexdigest(input_string)
    # Generate key pair
    key = OpenSSL::PKey::EC.new(curve_name)
    key.generate_key

    # Convert public key point to a binary string
    bn_string = key.public_key.to_bn.to_s(2)

    # Assuming the point format is uncompressed (0x04), we can slice the x and y coordinates
    x_coordinate = bn_string[1, 32] # Skip the first byte (0x04) and take 32 bytes
    y_coordinate = bn_string[33, 32] # Skip the first 33 bytes and take 32 bytes

    # DPoP JWT Header
    header = {
      typ: typ,
      alg: alg,
      jwk: {
        kty: "EC",
        use: "sig",
        crv: "P-256",
        x: Base64.urlsafe_encode64(x_coordinate, padding: false),
        y: Base64.urlsafe_encode64(y_coordinate, padding: false)
      }
    }

    header.delete(:jwk) if remove_jwk
    header[:jwk][:kty] = "invalid" if invalid_jwk

    # DPoP JWT Payload
    payload = {
      jti: jti, # Unique token identifier
      htm: htm, # HTTP method of the request to which the DPoP token is attached, in uppercase. Adjust accordingly.
      htu: htu, # HTTP URL of the request, adjust if different
      iat: time_now # Issued at
    }

    if bad_signature
      wrong_key = OpenSSL::PKey::EC.new(curve_name)
      wrong_key.generate_key
      dpop_token = JWT.encode(payload, wrong_key, alg, header)
    else
      dpop_token = JWT.encode(payload, key, alg, header)
    end

    dpop_token
  end

  def post_token_request
    post(
      "/token",
      client_id: oauth_application[:client_id],
      client_secret: "CLIENT_SECRET",
      grant_type: "authorization_code",
      code: oauth_grant[:code],
      redirect_uri: oauth_grant[:redirect_uri]
    )
  end
end
