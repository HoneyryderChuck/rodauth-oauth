# frozen_string_literal: true

require "test_helper"
require "webmock/minitest"

class RodauthOauthOIDCBackchannelLogoutAuthorizeTest < OIDCIntegration
  include WebMock::API
  include Rack::Test::Methods

  def test_oidc_authorize_id_token_post_authorize_with_sid
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_keys("RS256" => jws_key)
      oauth_jwt_public_keys("RS256" => jws_public_key)
    end
    oauth_application = set_oauth_application(backchannel_logout_uri: "http://logout.com")
    setup_application
    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&" \
          "response_type=id_token&state=STATE&nonce=NONCE"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"

    # submit authorization request
    click_button "Authorize"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#id_token=([^&]+)&state=STATE/,
           "was redirected instead to #{page.current_url}"

    assert db[:oauth_grants].count.zero?,
           "a grant has been created"
    id_token_claims = verify_id_token(Regexp.last_match(1), db[:oauth_grants].first, signing_key: jws_public_key, signing_algo: "RS256")
    assert id_token_claims.key?("sid")

    # now let's logout
    visit("/")
    stub_request(:post, "http://logout.com")
      .to_return(status: 204)

    logout

    assert_requested(:post, "http://logout.com") do |req|
      body = req.body
      assert body.match(/logout_token=(.+)/)
      params = URI.decode_www_form(body).to_h
      logout_token = params["logout_token"]

      logout_claims = verify_logout_token(logout_token, nil, signing_key: jws_public_key, signing_algo: "RS256")
      assert logout_claims.key?("sid")
      assert logout_claims["sid"] == id_token_claims["sid"]
    end
  end

  def test_oidc_authorize_id_token_post_authorize_without_sid
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      backchannel_logout_session_supported false
      oauth_jwt_keys("RS256" => jws_key)
      oauth_jwt_public_keys("RS256" => jws_public_key)
    end
    oauth_application = set_oauth_application(backchannel_logout_uri: "http://logout.com")
    setup_application
    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&" \
          "response_type=id_token&state=STATE&nonce=NONCE"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"

    # submit authorization request
    click_button "Authorize"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#id_token=([^&]+)&state=STATE/,
           "was redirected instead to #{page.current_url}"

    assert db[:oauth_grants].count.zero?,
           "a grant has been created"

    id_token_claims = verify_id_token(Regexp.last_match(1), db[:oauth_grants].first, signing_key: jws_public_key, signing_algo: "RS256")
    assert !id_token_claims.key?("sid")

    # now let's logout
    visit("/")
    stub_request(:post, "http://logout.com")
      .to_return(status: 204)
    logout

    assert_requested(:post, "http://logout.com") do |req|
      body = req.body
      assert body.match(/logout_token=(.+)/)
      params = URI.decode_www_form(body).to_h
      logout_token = params["logout_token"]

      logout_claims = verify_logout_token(logout_token, nil, signing_key: jws_public_key, signing_algo: "RS256")
      assert !logout_claims.key?("sid")
    end
  end

  def test_oidc_authorize_id_token_post_authorize_with_client_application_sid
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      backchannel_logout_session_supported false
      oauth_jwt_keys("RS256" => jws_key)
      oauth_jwt_public_keys("RS256" => jws_public_key)
    end
    oauth_application = set_oauth_application(backchannel_logout_session_required: true, backchannel_logout_uri: "http://logout.com?foo=bar")
    setup_application
    login

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&" \
          "response_type=id_token&state=STATE&nonce=NONCE&response_mode=query"
    assert current_url.include?("#error=invalid_request")

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&" \
          "response_type=id_token&state=STATE&nonce=NONCE"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"

    # submit authorization request
    click_button "Authorize"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#id_token=([^&]+)&state=STATE/,
           "was redirected instead to #{page.current_url}"

    assert db[:oauth_grants].count.zero?,
           "a grant has been created"
    id_token_claims = verify_id_token(Regexp.last_match(1), db[:oauth_grants].first, signing_key: jws_public_key, signing_algo: "RS256")
    assert id_token_claims.key?("sid")

    stub_request(:post, "http://logout.com?foo=bar")
      .to_return(status: 204)
    # now let's logout
    visit("/")
    logout

    assert_requested(:post, "http://logout.com?foo=bar") do |req|
      body = req.body
      assert body.match(/logout_token=(.+)/)
      params = URI.decode_www_form(body).to_h
      logout_token = params["logout_token"]

      logout_claims = verify_logout_token(logout_token, nil, signing_key: jws_public_key, signing_algo: "RS256")
      assert logout_claims.key?("sid")
    end
  end

  def test_oidc_authorize_code_post_authorize_with_sid
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_keys("RS256" => jws_key)
      oauth_jwt_public_keys("RS256" => jws_public_key)
    end
    oauth_application = set_oauth_application(backchannel_logout_uri: "http://logout.com")
    setup_application
    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&" \
          "response_type=code&state=STATE&nonce=NONCE"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"

    # submit authorization request
    click_button "Authorize"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}\?code=([^&]+)&state=STATE/,
           "was redirected instead to #{page.current_url}"

    assert db[:oauth_grants].count == 1,
           "no grant has been created"

    code = Regexp.last_match(1)
    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: code,
         redirect_uri: oauth_application[:redirect_uri])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert !json_body["id_token"].nil?
    id_token = json_body["id_token"]

    id_token_claims = verify_id_token(id_token, db[:oauth_grants].first, signing_key: jws_public_key, signing_algo: "RS256")
    assert id_token_claims.key?("sid")

    # now let's logout
    visit("/")
    stub_request(:post, "http://logout.com")
      .to_return(status: 204)

    logout

    assert_requested(:post, "http://logout.com") do |req|
      body = req.body
      assert body.match(/logout_token=(.+)/)
      params = URI.decode_www_form(body).to_h
      logout_token = params["logout_token"]

      logout_claims = verify_logout_token(logout_token, nil, signing_key: jws_public_key, signing_algo: "RS256")
      assert logout_claims.key?("sid")
      assert logout_claims["sid"] == id_token_claims["sid"]
    end
  end

  def test_oidc_authorize_code_post_authorize_without_sid
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      backchannel_logout_session_supported false
      oauth_jwt_keys("RS256" => jws_key)
      oauth_jwt_public_keys("RS256" => jws_public_key)
    end
    oauth_application = set_oauth_application(backchannel_logout_uri: "http://logout.com")
    setup_application
    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&" \
          "response_type=code&state=STATE&nonce=NONCE"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"

    # submit authorization request
    click_button "Authorize"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}\?code=([^&]+)&state=STATE/,
           "was redirected instead to #{page.current_url}"

    assert db[:oauth_grants].count == 1,
           "no grant has been created"

    code = Regexp.last_match(1)
    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: code,
         redirect_uri: oauth_application[:redirect_uri])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert !json_body["id_token"].nil?
    id_token = json_body["id_token"]

    id_token_claims = verify_id_token(id_token, db[:oauth_grants].first, signing_key: jws_public_key, signing_algo: "RS256")
    assert !id_token_claims.key?("sid")

    # now let's logout
    visit("/")
    stub_request(:post, "http://logout.com")
      .to_return(status: 204)
    logout

    assert_requested(:post, "http://logout.com") do |req|
      body = req.body
      assert body.match(/logout_token=(.+)/)
      params = URI.decode_www_form(body).to_h
      logout_token = params["logout_token"]

      logout_claims = verify_logout_token(logout_token, nil, signing_key: jws_public_key, signing_algo: "RS256")
      assert !logout_claims.key?("sid")
    end
  end

  def test_oidc_authorize_code_post_authorize_with_client_application_sid
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      backchannel_logout_session_supported false
      oauth_jwt_keys("RS256" => jws_key)
      oauth_jwt_public_keys("RS256" => jws_public_key)
    end
    oauth_application = set_oauth_application(backchannel_logout_session_required: true, backchannel_logout_uri: "http://logout.com?foo=bar")
    setup_application
    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&" \
          "response_type=code&state=STATE&nonce=NONCE"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"

    # submit authorization request
    click_button "Authorize"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}\?code=([^&]+)&state=STATE/,
           "was redirected instead to #{page.current_url}"

    assert db[:oauth_grants].count == 1,
           "no grant has been created"

    code = Regexp.last_match(1)
    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: code,
         redirect_uri: oauth_application[:redirect_uri])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert !json_body["id_token"].nil?
    id_token = json_body["id_token"]

    id_token_claims = verify_id_token(id_token, db[:oauth_grants].first, signing_key: jws_public_key, signing_algo: "RS256")
    assert id_token_claims.key?("sid")

    stub_request(:post, "http://logout.com?foo=bar")
      .to_return(status: 204)
    # now let's logout
    visit("/")
    logout

    assert_requested(:post, "http://logout.com?foo=bar") do |req|
      body = req.body
      assert body.match(/logout_token=(.+)/)
      params = URI.decode_www_form(body).to_h
      logout_token = params["logout_token"]

      logout_claims = verify_logout_token(logout_token, nil, signing_key: jws_public_key, signing_algo: "RS256")
      assert logout_claims.key?("sid")
    end
  end

  private

  def teardown
    WebMock.reset!
    super
  end

  def oauth_feature
    %i[oidc_backchannel_logout]
  end

  def setup_application(*)
    rodauth do
      # oauth_jwt_keys("RS256" => OpenSSL::PKey::RSA.generate(2048))
      oauth_applications_jwks_column :jwks
      oauth_response_mode "query"
    end
    super
  end
end
