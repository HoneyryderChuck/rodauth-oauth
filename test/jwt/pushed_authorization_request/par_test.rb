# frozen_string_literal: true

require "test_helper"
require "webmock/minitest"

class RodauthOauthJwtPushedAuthorizationRequestParTest < JWTIntegration
  include Rack::Test::Methods

  def test_par_successful_basic_auth_secured_request
    setup_application

    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key

    application = oauth_application(jwks: JSON.dump([JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256")]))

    signed_request = generate_signed_request(application, signing_key: jws_key)

    login
    post("/par", request: signed_request)

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_pushed_requests].count == 1,
           "no push request has been created"
    request = db[:oauth_pushed_requests].first
    assert request[:oauth_application_id] == application[:id]
    assert request[:params] == "response_mode=query&" \
                               "response_type=code&" \
                               "client_id=#{application[:client_id]}&" \
                               "redirect_uri=#{CGI.escape(application[:redirect_uri])}&" \
                               "scope=#{CGI.escape(application[:scopes])}&" \
                               "state=ABCDEF"

    assert json_body["request_uri"] == "urn:ietf:params:oauth:request_uri:#{request[:code]}"
    assert json_body["expires_in"] == 90

    # show the authorization form
    login_form
    visit "/authorize?client_id=#{application[:client_id]}&request_uri=urn:ietf:params:oauth:request_uri:#{request[:code]}"
    assert_includes page.html, "name=\"response_type\" value=\"code\""
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "user.read"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_grants].count == 1,
           "no grant has been created"

    oauth_grant = db[:oauth_grants].first

    assert page.current_url == "#{application[:redirect_uri]}?code=#{oauth_grant[:code]}&state=ABCDEF",
           "was redirected instead to #{page.current_url}"
  end

  private

  def setup_application(*)
    super
    header "Accept", "application/json"
  end

  def generate_signed_request(application, signing_key: OpenSSL::PKey::RSA.generate(2048), encryption_key: nil, **extra_claims)
    claims = {
      iss: application[:client_id],
      aud: "http://example.org",
      response_mode: "query",
      response_type: "code",
      client_id: application[:client_id],
      redirect_uri: application[:redirect_uri],
      scope: application[:scopes],
      state: "ABCDEF"
    }.merge(extra_claims)

    headers = {}

    jwk = JWT::JWK.new(signing_key)
    headers[:kid] = jwk.kid

    signing_key = jwk.keypair

    token = JWT.encode(claims, signing_key, "RS256", headers)

    if encryption_key
      params = {
        enc: "A128CBC-HS256",
        alg: "RSA-OAEP"
      }
      token = JWE.encrypt(token, encryption_key, **params)
    end

    token
  end

  alias login_form login
  # overriding to implement the client/secret basic authorization
  def login
    header "Authorization", "Basic #{authorization_header(
      username: oauth_application[:client_id],
      password: 'CLIENT_SECRET'
    )}"
  end

  def oauth_feature
    %i[oauth_authorization_code_grant oauth_jwt_secured_authorization_request oauth_pushed_authorization_request]
  end
end
