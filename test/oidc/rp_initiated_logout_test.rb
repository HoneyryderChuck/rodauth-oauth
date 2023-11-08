# frozen_string_literal: true

require "test_helper"

class RodauthOAuthOIDCRpInitiatedLogoutTest < OIDCIntegration
  include Rack::Test::Methods

  def test_oidc_rp_initiated_logout
    client_application = oauth_application(post_logout_redirect_uris: "https://example.com/logout")

    rodauth do
      oauth_jwt_keys("RS256" => OpenSSL::PKey::RSA.generate(2048))
    end
    setup_application(:oidc_rp_initiated_logout)

    login

    id_token = generate_id_token(client_application)

    visit "/oidc-logout?id_token_hint=#{id_token}"
    assert page.current_path == "/login",
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_rp_initiated_logout_from_post_logout_param
    client_application = oauth_application(post_logout_redirect_uris: "https://example.com/logout")

    rodauth do
      oauth_jwt_keys("RS256" => OpenSSL::PKey::RSA.generate(2048))
    end
    setup_application(:oidc_rp_initiated_logout)
    login

    id_token = generate_id_token(client_application)

    visit "/oidc-logout?id_token_hint=#{id_token}&post_logout_redirect_uri=https://example.com/logout"
    assert page.current_url == "https://example.com/logout",
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_rp_initiated_logout_from_post_logout_param_multiple_urls
    client_application = oauth_application(post_logout_redirect_uris: "https://example.com/logout https://example.com/callback")

    rodauth do
      oauth_jwt_keys("RS256" => OpenSSL::PKey::RSA.generate(2048))
    end
    setup_application(:oidc_rp_initiated_logout)
    login

    id_token = generate_id_token(client_application)

    visit "/oidc-logout?id_token_hint=#{id_token}&post_logout_redirect_uri=https://example.com/callback"
    assert page.current_url == "https://example.com/callback",
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_rp_initiated_logout_with_state
    client_application = oauth_application(post_logout_redirect_uris: "https://example.com/logout")

    rodauth do
      oauth_jwt_keys("RS256" => OpenSSL::PKey::RSA.generate(2048))
    end
    setup_application(:oidc_rp_initiated_logout)
    login

    id_token = generate_id_token(client_application)

    visit "/oidc-logout?id_token_hint=#{id_token}&post_logout_redirect_uri=https://example.com/logout&state=STATE"
    assert page.current_url == "https://example.com/logout?state=STATE",
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_rp_initiated_logout_from_post_logout_param_id_token
    client_application = oauth_application(post_logout_redirect_uris: "https://example.com/logout")

    rodauth do
      oauth_jwt_keys("RS256" => OpenSSL::PKey::RSA.generate(2048))
    end
    setup_application(:oidc_rp_initiated_logout)
    login

    id_token = generate_id_token(client_application, "id_token")

    visit "/oidc-logout?id_token_hint=#{id_token}&post_logout_redirect_uri=https://example.com/logout"
    assert page.current_url == "https://example.com/logout",
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_rp_initiated_logout_with_frontchannel
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_keys("RS256" => jws_key)
    end
    setup_application(:oidc_rp_initiated_logout, :oidc_frontchannel_logout)

    client_application = oauth_application(frontchannel_logout_uri: "http://logout.com", post_logout_redirect_uris: "https://example.com/logout")
    login

    id_token = generate_id_token(client_application)
    claims = verify_id_token(id_token, nil, signing_key: jws_public_key, signing_algo: "RS256")

    visit "/oidc-logout?id_token_hint=#{id_token}&post_logout_redirect_uri=https://example.com/logout"

    assert_includes page.html, "<iframe src=\"http://logout.com?iss=" \
                               "#{CGI.escape('http://www.example.com')}&" \
                               "sid=#{claims['sid']}\">"

    assert_includes page.html, "<meta http-equiv=\"refresh\" content=\"5; " \
                               "URL=https://example.com/logout\" />"
  end

  private

  def setup_application(*args)
    rodauth do
      oauth_jwt_keys("RS256" => OpenSSL::PKey::RSA.generate(2048))
    end
    super(:oidc_rp_initiated_logout, *args)
  end

  def generate_id_token(application = oauth_application, response_type = "code+id_token")
    visit "/authorize?client_id=#{application[:client_id]}&scope=openid&response_type=#{response_type}&nonce=NONCE"
    check "openid"
    click_button "Authorize"
    assert page.current_url.start_with?("https://example.com/callback"),
           "was redirected instead to #{page.current_url}"
    token_url = URI(page.current_url)
    params = Hash[token_url.fragment.split("&").map { |p| p.split("=") }]
    params["id_token"]
  end
end
