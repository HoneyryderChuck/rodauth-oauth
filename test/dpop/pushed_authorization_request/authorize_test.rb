# frozen_string_literal: true

require "test_helper"

class RodauthOauthDpopPushedAuthorizationRequestAuthorizeTest < DPoPIntegration
  include Rack::Test::Methods

  def test_authorize_post_authorize_par_dpop_jkt_in_par_request
    setup_application
    login

    dpop_key = OpenSSL::PKey::RSA.generate(2048)
    dpop_public_key = dpop_key.public_key
    jkt = generate_thumbprint(dpop_public_key)

    header "Authorization", "Basic #{authorization_header(
      username: oauth_application[:client_id],
      password: 'CLIENT_SECRET'
    )}"
    # include dpop_jkt
    post("/par",
         response_type: "code",
         scope: "user.read",
         redirect_uri: oauth_application[:redirect_uri],
         dpop_jkt: jkt)

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_pushed_requests].one?,
           "no push request has been created"
    request = db[:oauth_pushed_requests].first
    assert request[:oauth_application_id] == oauth_application[:id]

    assert json_body["request_uri"] == "urn:ietf:params:oauth:request_uri:#{request[:code]}"

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&request_uri=urn:ietf:params:oauth:request_uri:#{request[:code]}"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "user.read"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_grants].one?,
           "no grant has been created"

    oauth_grant = db[:oauth_grants].first

    assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{oauth_grant[:code]}",
           "was redirected instead to #{page.current_url}"

    assert oauth_grant[:dpop_jkt] == jkt
  end

  def test_authorize_post_authorize_par_dpop_header_in_par_request
    setup_application
    login

    dpop_key = OpenSSL::PKey::RSA.generate(2048)
    dpop_public_key = dpop_key.public_key
    jkt = generate_thumbprint(dpop_public_key)

    header "Authorization", "Basic #{authorization_header(
      username: oauth_application[:client_id],
      password: 'CLIENT_SECRET'
    )}"

    header "DPoP", generate_dpop_proof(dpop_key, request_uri: "http://example.org/par")
    post("/par",
         response_type: "code",
         scope: "user.read",
         redirect_uri: oauth_application[:redirect_uri])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_pushed_requests].one?,
           "no push request has been created"
    request = db[:oauth_pushed_requests].first
    assert request[:oauth_application_id] == oauth_application[:id]

    assert json_body["request_uri"] == "urn:ietf:params:oauth:request_uri:#{request[:code]}"

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&request_uri=urn:ietf:params:oauth:request_uri:#{request[:code]}"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "user.read"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_grants].one?,
           "no grant has been created"

    oauth_grant = db[:oauth_grants].first

    assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{oauth_grant[:code]}",
           "was redirected instead to #{page.current_url}"

    assert oauth_grant[:dpop_jkt] == jkt
  end

  def test_authorize_post_authorize_par_dpop_jkt_and_header_reject_if_both_not_match
    setup_application
    login

    dpop_key = OpenSSL::PKey::RSA.generate(2048)
    dpop_public_key = dpop_key.public_key
    jkt = generate_thumbprint(dpop_public_key)
    fake_jkt = generate_thumbprint(OpenSSL::PKey::RSA.generate(2048))

    header "Authorization", "Basic #{authorization_header(
      username: oauth_application[:client_id],
      password: 'CLIENT_SECRET'
    )}"

    header "DPoP", generate_dpop_proof(dpop_key, request_uri: "http://example.org/par")
    post("/par",
         response_type: "code",
         scope: "user.read",
         redirect_uri: oauth_application[:redirect_uri],
         dpop_jkt: fake_jkt)

    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"

    @json_body = nil

    post("/par",
         response_type: "code",
         scope: "user.read",
         redirect_uri: oauth_application[:redirect_uri],
         dpop_jkt: jkt)

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_pushed_requests].one?,
           "no push request has been created"
    request = db[:oauth_pushed_requests].first
    assert request[:oauth_application_id] == oauth_application[:id]

    assert json_body["request_uri"] == "urn:ietf:params:oauth:request_uri:#{request[:code]}"
  end

  private

  def setup_application(*)
    rodauth do
      oauth_response_mode "query"
    end
    super
  end

  def oauth_feature
    %i[oauth_authorization_code_grant oauth_pushed_authorization_request oauth_dpop]
  end
end
