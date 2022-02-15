# frozen_string_literal: true

require "test_helper"

class RodauthOauthPkceAuthorizeTest < RodaIntegration
  def test_authorize_post_authorize_with_pkce
    setup_application

    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&" \
          "code_challenge=#{PKCE_CHALLENGE}&code_challenge_method=S256"

    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_grants].count == 1,
           "no grant has been created"

    oauth_grant = db[:oauth_grants].first
    assert oauth_grant[:code_challenge] == PKCE_CHALLENGE
    assert oauth_grant[:code_challenge_method] == "S256"

    assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{oauth_grant[:code]}",
           "was redirected instead to #{page.current_url}"
  end

  def test_authorize_post_authorize_with_pkce_disabled
    rodauth do
      use_oauth_pkce? false
    end
    setup_application

    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&" \
          "code_challenge=#{PKCE_CHALLENGE}&code_challenge_method=S256"

    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_grants].count == 1,
           "no grant has been created"

    oauth_grant = db[:oauth_grants].first
    assert oauth_grant[:code_challenge].nil?
    assert oauth_grant[:code_challenge_method].nil?

    assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{oauth_grant[:code]}",
           "was redirected instead to #{page.current_url}"
  end

  def test_authorize_post_authorize_with_forced_pkce_no_challenge
    rodauth do
      oauth_require_pkce true
    end
    setup_application

    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}"

    assert page.current_url.include?("?error=invalid_request"),
           "code challenge required"
  end
end
