# frozen_string_literal: true

require "test_helper"

class RodauthOauthPushedAuthorizationRequestAuthorizeTest < RodaIntegration
  def test_authorize_get_public_area
    setup_application
    visit "/"
    assert page.html.include?("Unauthorized")
  end

  def test_authorize_get_authorize_not_logged_in_no_client_application
    setup_application
    visit "/authorize"

    assert page.current_path == "/login",
           "was redirected instead to #{page.current_path}"
  end

  def test_authorize_get_authorize_no_client_application
    setup_application
    login
    visit "/authorize"

    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    assert_includes page.html, "Invalid or missing 'client_id'"
    assert_includes page.html, "Cancel"
  end

  def test_authorize_get_authorize_invalid_client_id
    setup_application
    login
    visit "/authorize?client_id=bla"

    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    assert_includes page.html, "Invalid or missing 'client_id'"
    assert_includes page.html, "Cancel"
  end

  def test_authorize_post_authorize_client_client_application_required_par
    oauth_application = set_oauth_application(require_pushed_authorization_requests: true)
    setup_application
    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&response_type=code&scope=user.read+user.write&response_type=code"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    assert_includes page.html, "Invalid or missing 'request_uri'"
    assert_includes page.html, "Cancel"
  end

  def test_authorize_post_authorize_server_providerr_required_par
    rodauth do
      oauth_require_pushed_authorization_requests true
    end
    setup_application
    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&response_type=code&scope=user.read+user.write&response_type=code"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    assert_includes page.html, "Invalid or missing 'request_uri'"
    assert_includes page.html, "Cancel"
  end

  def test_authorize_post_authorize_par_expired
    setup_application
    login

    push_request = set_push_request(code: "CODE", expires_in: Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, seconds: 3))

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&request_uri=urn:ietf:params:oauth:request_uri:#{push_request[:code]}"
    assert page.current_url.include?("?error=invalid_request"),
           "was redirected instead to #{page.current_url}"
  end

  def test_authorize_post_authorize_par
    setup_application
    login

    push_request = set_push_request(code: "CODE")

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&request_uri=urn:ietf:params:oauth:request_uri:#{push_request[:code]}"
    assert_includes page.html, "name=\"response_type\" value=\"code\""
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "user.read"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_grants].count == 1,
           "no grant has been created"

    oauth_grant = db[:oauth_grants].first

    assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{oauth_grant[:code]}",
           "was redirected instead to #{page.current_url}"
  end

  private

  def setup_application(*)
    rodauth do
      oauth_response_mode "query"
    end
    super
  end

  def oauth_feature
    %i[oauth_authorization_code_grant oauth_pushed_authorization_request]
  end
end
