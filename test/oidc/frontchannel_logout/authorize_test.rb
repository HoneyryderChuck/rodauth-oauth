# frozen_string_literal: true

require "test_helper"

class RodauthOauthOIDCFrontchannelLogoutAuthorizeTest < OIDCIntegration
  include Rack::Test::Methods

  def test_oidc_authorize_id_token_post_authorize_with_sid
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_keys("RS256" => jws_key)
      oauth_jwt_public_keys("RS256" => jws_public_key)
    end
    oauth_application = set_oauth_application(frontchannel_logout_uri: "http://logout.com")
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
    claims = verify_id_token(Regexp.last_match(1), db[:oauth_grants].first, signing_key: jws_public_key, signing_algo: "RS256")
    assert claims.key?("sid")

    # now let's logout
    visit("/")
    logout

    assert_includes page.html, "<iframe src=\"http://logout.com?iss=" \
                               "#{CGI.escape('http://www.example.com')}&" \
                               "sid=#{claims['sid']}\">"
  end

  def test_oidc_authorize_id_token_post_authorize_without_sid
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      frontchannel_logout_session_supported false
      oauth_jwt_keys("RS256" => jws_key)
      oauth_jwt_public_keys("RS256" => jws_public_key)
    end
    oauth_application = set_oauth_application(frontchannel_logout_uri: "http://logout.com")
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
    claims = verify_id_token(Regexp.last_match(1), db[:oauth_grants].first, signing_key: jws_public_key, signing_algo: "RS256")
    assert !claims.key?("sid")

    # now let's logout
    visit("/")
    logout

    assert_includes page.html, "<iframe src=\"http://logout.com\">"
  end

  def test_oidc_authorize_id_token_post_authorize_with_client_application_sid
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      frontchannel_logout_session_supported false
      oauth_jwt_keys("RS256" => jws_key)
      oauth_jwt_public_keys("RS256" => jws_public_key)
    end
    oauth_application = set_oauth_application(frontchannel_logout_session_required: true, frontchannel_logout_uri: "http://logout.com?foo=bar")
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
    claims = verify_id_token(Regexp.last_match(1), db[:oauth_grants].first, signing_key: jws_public_key, signing_algo: "RS256")
    assert claims.key?("sid")

    # now let's logout
    visit("/")
    logout

    assert_includes page.html, "<iframe src=\"http://logout.com?foo=bar&iss=" \
                               "#{CGI.escape('http://www.example.com')}&" \
                               "sid=#{claims['sid']}\">"
  end

  def test_oidc_authorize_code_post_authorize_with_sid
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_keys("RS256" => jws_key)
      oauth_jwt_public_keys("RS256" => jws_public_key)
    end
    oauth_application = set_oauth_application(frontchannel_logout_uri: "http://logout.com")
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

    claims = verify_id_token(id_token, db[:oauth_grants].first, signing_key: jws_public_key, signing_algo: "RS256")
    assert claims.key?("sid")

    # now let's logout
    visit("/")
    logout

    assert_includes page.html, "<iframe src=\"http://logout.com?iss=" \
                               "#{CGI.escape('http://www.example.com')}&" \
                               "sid=#{claims['sid']}\">"
  end

  def test_oidc_authorize_code_post_authorize_without_sid
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      frontchannel_logout_session_supported false
      oauth_jwt_keys("RS256" => jws_key)
      oauth_jwt_public_keys("RS256" => jws_public_key)
    end
    oauth_application = set_oauth_application(frontchannel_logout_uri: "http://logout.com")
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

    claims = verify_id_token(id_token, db[:oauth_grants].first, signing_key: jws_public_key, signing_algo: "RS256")
    assert !claims.key?("sid")

    # now let's logout
    visit("/")
    logout

    assert_includes page.html, "<iframe src=\"http://logout.com\">"
  end

  def test_oidc_authorize_code_post_authorize_with_client_application_sid
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      frontchannel_logout_session_supported false
      oauth_jwt_keys("RS256" => jws_key)
      oauth_jwt_public_keys("RS256" => jws_public_key)
    end
    oauth_application = set_oauth_application(frontchannel_logout_session_required: true, frontchannel_logout_uri: "http://logout.com?foo=bar")
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

    claims = verify_id_token(id_token, db[:oauth_grants].first, signing_key: jws_public_key, signing_algo: "RS256")
    assert claims.key?("sid")

    # now let's logout
    visit("/")
    logout

    assert_includes page.html, "<iframe src=\"http://logout.com?foo=bar&iss=" \
                               "#{CGI.escape('http://www.example.com')}&" \
                               "sid=#{claims['sid']}\">"
  end

  private

  def oauth_feature
    %i[oidc_frontchannel_logout]
  end

  def setup_application(*)
    rodauth do
      oauth_jwt_keys("RS256" => OpenSSL::PKey::RSA.generate(2048))
      oauth_applications_jwks_column :jwks
      oauth_response_mode "query"
    end
    super
  end
end
