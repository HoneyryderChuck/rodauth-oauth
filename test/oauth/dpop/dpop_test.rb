# frozen_string_literal: true

require "test_helper"
require "webmock/minitest"
# require_relative "../../../lib/rodauth/features/oauth_dpop"

class RodauthOAuthDPoPTest < JWTIntegration
  include Rack::Test::Methods

  def test_access_token_generation_with_dpop_proof
    setup_application

    # Make a request with DPoP headers to generate an access token
    header "DPoP", generate_dpop_proof("http://example.org")
    post(
      "/token",
      client_secret: "CLIENT_SECRET",
      client_id: oauth_application[:client_id],
      grant_type: "authorization_code",
      redirect_uri: oauth_grant[:redirect_uri],
      code: oauth_grant[:code]
    ) # Replace 'your_code_here' with a valid authorization code

    assert_equal 200, last_response.status
    refute_nil json_body["access_token"]
  end

  def test_access_protected_resource_with_dpop_token
    rodauth { oauth_dpop_bound_access_tokens true }
    setup_application

    token = generate_access_token(oauth_grant(scopes: "openid"))
    login(token)

    @json_body = nil

    # Access the protected resource with the token
    headers = { "Authorization" => "Bearer #{token}" }
    get "/private", {}, headers

    assert_equal 200, last_response.status
    # Additional assertions related to the response data can be added here
  end

  def test_fail_generation_without_dpop_when_dpop_bound_is_true
    rodauth { oauth_dpop_bound_access_tokens true }
    setup_application

    post(
      "/token",
      client_id: oauth_application[:client_id],
      client_secret: "CLIENT_SECRET",
      grant_type: "authorization_code",
      code: oauth_grant[:code],
      redirect_uri: oauth_grant[:redirect_uri]
    )

    assert last_response.status == 400 || last_response.status == 401

    assert json_body["error"]
  end

  private

  def setup_application(*)
    rodauth { oauth_jwt_keys("HS256" => "SECRET") }
    super
    header "Accept", "application/json"
  end

  def oauth_feature
    %i[oauth_authorization_code_grant oauth_dpop]
  end

  def generate_access_token(grant)
    header "Authorization",
           "Basic #{
             authorization_header(
               username: oauth_application[:client_id],
               password: "CLIENT_SECRET"
             )
           }"
    header "DPoP", generate_dpop_proof("http://example.org")
    post(
      "/token",
      client_id: oauth_application[:client_id],
      client_secret: "CLIENT_SECRET",
      grant_type: "authorization_code",
      code: grant[:code],
      redirect_uri: grant[:redirect_uri]
    )

    puts "json_body: #{json_body}"

    puts "access_token: #{json_body["access_token"]}"
    json_body["access_token"]
  end

  def login(token)
    header "Authorization",
           "Basic #{
             authorization_header(
               username: oauth_application[:client_id],
               password: "CLIENT_SECRET"
             )
           }"
  end

  def generate_dpop_proof(iss)
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
      typ: "dpop+jwt",
      alg: "ES256",
      jwk: {
        kty: "EC",
        use: "sig",
        crv: "P-256",
        x: Base64.urlsafe_encode64(x_coordinate, padding: false),
        y: Base64.urlsafe_encode64(y_coordinate, padding: false)
      }
    }

    # DPoP JWT Payload
    payload = {
      jti: jti, # Unique token identifier
      htm: "POST", # HTTP method of the request to which the DPoP token is attached, in uppercase. Adjust accordingly.
      htu: "#{iss}/token", # HTTP URL of the request, adjust if different
      iat: time_now # Issued at
    }

    # Encode the JWT
    dpop_token = JWT.encode(payload, key, "ES256", header)

    return dpop_token
  end
end
