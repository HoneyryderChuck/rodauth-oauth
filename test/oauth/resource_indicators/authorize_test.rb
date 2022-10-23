# frozen_string_literal: true

require "test_helper"

class RodauthOauthResourceIndicatorsAuthorizeTest < RodaIntegration
  def test_authorize_one_resource_not_uri
    rodauth do
      oauth_application_scopes %w[read write]
    end
    setup_application
    login
    visit "/authorize?client_id=#{oauth_application[:client_id]}&response_type=code&resource=bla"
    assert page.current_url.end_with?("?error=invalid_target"),
           "was redirected instead to #{page.current_url}"
  end

  def test_authorize_one_resource_uri_with_fragment
    setup_application
    login
    visit "/authorize?client_id=#{oauth_application[:client_id]}&response_type=code&resource=#{CGI.escape('https://resource.com#bla=bla')}"
    assert page.current_url.end_with?("?error=invalid_target"),
           "was redirected instead to #{page.current_url}"
  end

  def test_authorize_one_resource_valid
    setup_application
    login
    visit "/authorize?client_id=#{oauth_application[:client_id]}&resource=#{CGI.escape('https://resource.com')}&response_type=code&response_mode=query"
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
    assert oauth_grant[:resource] == "https://resource.com"
    assert oauth_grant[:scopes] == "user.read"
  end

  def test_authorize_multi_resource_valid
    skip # capybara rack-test does not support same param 2 times in form submit
    setup_application
    login
    visit "/authorize?client_id=#{oauth_application[:client_id]}&response_type=code&" \
          "resource=#{CGI.escape('https://resource.com')}&resource=#{CGI.escape('https://resource2.com')}"
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
    assert oauth_grant[:resource] == "https://resource.com https://resource2.com"
    assert oauth_grant[:scopes] == "user.read"
  end

  private

  def oauth_feature
    %i[oauth_authorization_code_grant oauth_resource_indicators]
  end
end
