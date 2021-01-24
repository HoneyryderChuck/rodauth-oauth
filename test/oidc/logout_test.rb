# frozen_string_literal: true

require "test_helper"

class RodauthOAuthOIDCLogoutTest < OIDCIntegration
  include Rack::Test::Methods

  def test_oidc_rp_initiated_logout_disabled
    rodauth do
      use_oauth_implicit_grant_type? true
      use_rp_initiated_logout? false
    end
    setup_application
    login

    id_token = generate_id_token

    visit "/oidc-logout?id_token_hint=#{id_token}&client_id=#{oauth_application[:client_id]}"
    assert page.current_url.include?("?error=invalid_request"),
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_rp_initiated_logout
    rodauth do
      use_oauth_implicit_grant_type? true
      use_rp_initiated_logout? true
    end
    client_application = oauth_application(post_logout_redirect_uri: "https://example.com/logout")

    setup_application
    login

    id_token = generate_id_token(client_application)

    visit "/oidc-logout?id_token_hint=#{id_token}"
    assert page.current_url == "/",
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_rp_initiated_logout_from_post_logout_param
    rodauth do
      use_oauth_implicit_grant_type? true
      use_rp_initiated_logout? true
    end
    client_application = oauth_application(post_logout_redirect_uri: "https://example.com/logout")

    setup_application
    login

    id_token = generate_id_token(client_application)

    visit "/oidc-logout?id_token_hint=#{id_token}&post_logout_redirect_uri=https://example.com/logout"
    assert page.current_url == "https://example.com/logout",
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_rp_initiated_logout_from_post_logout_param_multiple_urls
    rodauth do
      use_oauth_implicit_grant_type? true
      use_rp_initiated_logout? true
    end
    client_application = oauth_application(post_logout_redirect_uri: "https://example.com/logout https://example.com/other-logout")

    setup_application
    login

    id_token = generate_id_token(client_application)

    visit "/oidc-logout?id_token_hint=#{id_token}&post_logout_redirect_uri=https://example.com/other-logout"
    assert page.current_url == "https://example.com/other-logout",
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_rp_initiated_logout_with_state
    rodauth do
      use_oauth_implicit_grant_type? true
      use_rp_initiated_logout? true
    end
    client_application = oauth_application(post_logout_redirect_uri: "https://example.com/logout")

    setup_application
    login

    id_token = generate_id_token(client_application)

    visit "/oidc-logout?id_token_hint=#{id_token}&post_logout_redirect_uri=https://example.com/logout&state=STATE"
    assert page.current_url == "https://example.com/logout&state=STATE",
           "was redirected instead to #{page.current_url}"
  end

  private

  def generate_id_token(application = oauth_application)
    visit "/authorize?client_id=#{application[:client_id]}&scope=openid&response_type=code+id_token"
    click_button "Authorize"
    token_url = URI(page.current_url)
    params = Hash[token_url.fragment.split("&").map { |p| p.split("=") }]
    params["id_token"]
  end
end
