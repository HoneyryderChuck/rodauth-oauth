# frozen_string_literal: true

require "test_helper"

class RodaOauthAuthorizeTest < RodauthTest
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
    assert page.current_url.include?("?error=invalid_scope"),
           "was redirected instead to #{page.current_url}"
  end

  def test_authorize_post_authorize
    setup_application
    login

    # show the authorization form
    visit "/oauth-authorize?client_id=#{oauth_application[:client_id]}&scopes=user.read+user.write"
    assert page.current_path == "/oauth-authorize",
           "was redirected instead to #{page.current_path}"

    # submit authorization request
    click_button "Authorize"

    assert DB[:oauth_grants].count == 1,
           "no grant has been created"

    oauth_grant = DB[:oauth_grants].first

    assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{oauth_grant[:code]}",
           "was redirected instead to #{page.current_url}"
    assert oauth_grant[:access_type] == "offline"
  end

  def test_authorize_post_authorize_access_type_online
    setup_application
    login

    # show the authorization form
    visit "/oauth-authorize?client_id=#{oauth_application[:client_id]}&scopes=user.read+user.write&access_type=online"
    assert page.current_path == "/oauth-authorize",
           "was redirected instead to #{page.current_path}"

    # submit authorization request
    click_button "Authorize"

    assert DB[:oauth_grants].count == 1,
           "no grant has been created"

    oauth_grant = DB[:oauth_grants].first

    assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{oauth_grant[:code]}",
           "was redirected instead to #{page.current_url}"
    assert oauth_grant[:access_type] == "online"
  end

  def test_authorize_post_authorize_with_state
    setup_application
    login

    # show the authorization form
    visit "/oauth-authorize?client_id=#{oauth_application[:client_id]}&state=STATE"
    assert page.current_path == "/oauth-authorize",
           "was redirected instead to #{page.current_path}"

    # submit authorization request
    click_button "Authorize"

    assert DB[:oauth_grants].count == 1,
           "no grant has been created"

    oauth_grant = DB[:oauth_grants].first

    assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{oauth_grant[:code]}&state=STATE",
           "was redirected instead to #{page.current_url}"
  end

  def test_authorize_post_authorize_no_implicit_grant
    setup_application
    login

    # show the authorization form
    visit "/oauth-authorize?client_id=#{oauth_application[:client_id]}&scopes=user.read+user.write&response_type=token"
    assert page.current_path == "/oauth-authorize",
           "was redirected instead to #{page.current_path}"

    # submit authorization request
    click_button "Authorize"

    assert page.current_url.include?("?error=unsupported_grant_type"),
           "was redirected instead to #{page.current_url}"
  end

  def test_authorize_post_authorize_with_implicit_grant
    setup_application do |rodauth|
      rodauth.use_oauth_implicit_grant_type true
    end

    login

    # show the authorization form
    visit "/oauth-authorize?client_id=#{oauth_application[:client_id]}&&response_type=token"
    assert page.current_path == "/oauth-authorize",
           "was redirected instead to #{page.current_path}"

    # submit authorization request
    click_button "Authorize"

    assert DB[:oauth_tokens].count == 1,
           "no grant has been created"

    oauth_token = DB[:oauth_tokens].first

    assert page.current_url == "#{oauth_application[:redirect_uri]}?access_token=#{oauth_token[:token]}",
           "was redirected instead to #{page.current_url}"
  end
end
