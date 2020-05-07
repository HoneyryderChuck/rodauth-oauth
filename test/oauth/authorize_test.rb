# frozen_string_literal: true

require "test_helper"

class RodaOauthAuthorizeTest < RodauthTest
  include Capybara::DSL

  def test_authorize_get_public_area
    setup_application
    visit "/"
    assert page.html == "Unauthorized"
  end

  def test_authorize_get_authorize_not_logged_in_no_client_application
    setup_application
    visit "/oauth-authorize"
    assert page.current_path == "/login",
           "was redirected instead to #{page.current_path}"
  end

  def test_authorize_get_authorize
    setup_application
    login
    visit "/oauth-authorize"
    assert page.current_path == "/",
           "was redirected instead to #{page.current_path}"
  end

  def test_authorize_get_authorize_invalid_client_id
    setup_application
    login
    visit "/oauth-authorize?client_id=bla"
    assert page.current_url.end_with?("/?error=invalid_request"),
           "was redirected instead to #{page.current_url}"
  end

  def test_authorize_get_authorize_invalid_redirect_uri
    setup_application
    login
    visit "/oauth-authorize?client_id=#{oauth_application[:client_id]}&redirect_uri=bla"
    assert page.current_url.end_with?("/?error=invalid_request"),
           "was redirected instead to #{page.current_url}"
  end

  def test_authorize_get_authorize_invalid_scope
    setup_application
    login
    visit "/oauth-authorize?client_id=#{oauth_application[:client_id]}& "\
          "redirect_uri=#{oauth_application[:redirect_uri]}&" \
          "scopes=marvel"
    assert page.current_url.end_with?("/?error=invalid_scope"),
           "was redirected instead to #{page.current_url}"
  end

  def test_authorize_post_authorize
    setup_application
    login

    # show the authorization form
    visit "/oauth-authorize?client_id=#{oauth_application[:client_id]}"
    assert page.current_path == "/oauth-authorize",
           "was redirected instead to #{page.current_path}"

    # submit authorization request
    click_button "Authorize"
    # TODO: it's redirecting from fallback to root, fix it
    assert page.current_host == oauth_application[:homepage_url],
           "was redirected instead to #{page.current_url}"

    assert DB[:oauth_grants].count == 1,
           "no grant has been created"
  end
end
