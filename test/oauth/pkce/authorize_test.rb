# frozen_string_literal: true

require "test_helper"

class RodauthOauthPkceAuthorizeTest < RodaIntegration
  def test_authorize_post_authorize_with_pkce
    setup_application(:oauth_pkce)

    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&" \
          "code_challenge=#{PKCE_CHALLENGE}&code_challenge_method=S256&response_mode=query&response_type=code"

    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "user.read"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_grants].one?,
           "no grant has been created"

    oauth_grant = db[:oauth_grants].first
    assert oauth_grant[:code_challenge] == PKCE_CHALLENGE
    assert oauth_grant[:code_challenge_method] == "S256"

    assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{oauth_grant[:code]}",
           "was redirected instead to #{page.current_url}"
  end

  def test_authorize_post_authorize_with_pkce_disabled
    setup_application

    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&" \
          "code_challenge=#{PKCE_CHALLENGE}&code_challenge_method=S256&response_mode=query&response_type=code"

    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "user.read"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_grants].one?,
           "no grant has been created"

    oauth_grant = db[:oauth_grants].first
    assert oauth_grant[:code_challenge].nil?
    assert oauth_grant[:code_challenge_method].nil?

    assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{oauth_grant[:code]}",
           "was redirected instead to #{page.current_url}"
  end

  def test_authorize_post_authorize_with_forced_pkce_no_challenge
    setup_application(:oauth_pkce)

    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&response_type=code&response_mode=query"

    assert page.current_url.include?("?error=invalid_request"),
           "code challenge required"
  end

  def test_authorize_post_authorize_with_plain_pkce_rejected_by_default
    setup_application(:oauth_pkce)

    login

    # plain is disabled by default, so the authorization request must be rejected
    visit "/authorize?client_id=#{oauth_application[:client_id]}&" \
          "code_challenge=#{PKCE_VERIFIER}&code_challenge_method=plain&response_mode=query&response_type=code"

    assert page.current_url.include?("?error=invalid_request"),
           "plain challenge should be rejected by default"
    assert db[:oauth_grants].count.zero?,
           "a grant was created for a disabled challenge method"
  end

  def test_authorize_post_authorize_with_plain_pkce_when_allowed
    rodauth do
      oauth_pkce_allow_plain_method true
    end
    setup_application(:oauth_pkce)

    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&" \
          "code_challenge=#{PKCE_VERIFIER}&code_challenge_method=plain&response_mode=query&response_type=code"

    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "user.read"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_grants].one?,
           "no grant has been created"

    oauth_grant = db[:oauth_grants].first
    assert oauth_grant[:code_challenge] == PKCE_VERIFIER
    assert oauth_grant[:code_challenge_method] == "plain"
  end

  def test_authorize_post_authorize_with_unrequired_pkce
    rodauth do
      oauth_require_pkce false
    end
    setup_application(:oauth_pkce)

    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&response_type=code"

    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
  end
end
