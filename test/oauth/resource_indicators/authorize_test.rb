# frozen_string_literal: true

require "test_helper"

class RodauthOauthResourceIndicatorsAuthorizeTest < RodaIntegration
  def test_authorize_one_resource_not_uri
    rodauth do
      enable :oauth_resource_indicators
      oauth_application_scopes %w[read write]
    end
    setup_application
    login
    visit "/authorize?client_id=#{oauth_application[:client_id]}&resource=bla"
    assert page.current_url.end_with?("?error=invalid_target"),
           "was redirected instead to #{page.current_url}"
  end

  def test_authorize_one_resource_uri_with_fragment
    rodauth do
      enable :oauth_resource_indicators
      oauth_application_scopes %w[read write]
    end
    setup_application
    login
    visit "/authorize?client_id=#{oauth_application[:client_id]}&resource=#{CGI.escape('https://resource.com#bla=bla')}"
    assert page.current_url.end_with?("?error=invalid_target"),
           "was redirected instead to #{page.current_url}"
  end

  def test_authorize_one_resource_valid
    rodauth do
      enable :oauth_resource_indicators
      oauth_application_scopes %w[read write]
    end
    setup_application
    login
    visit "/authorize?client_id=#{oauth_application[:client_id]}&resource=#{CGI.escape('https://resource.com')}"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_grants].count == 1,
           "no grant has been created"

    oauth_grant = db[:oauth_grants].first

    assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{oauth_grant[:code]}",
           "was redirected instead to #{page.current_url}"
    assert oauth_grant[:resource] == "https://resource.com"
  end

  def test_authorize_multi_resource_valid
    skip # capybara rack-test does not support same param 2 times in form submit
    rodauth do
      enable :oauth_resource_indicators
      oauth_application_scopes %w[read write]
    end
    setup_application
    login
    visit "/authorize?client_id=#{oauth_application[:client_id]}&resource=#{CGI.escape('https://resource.com')}&resource=#{CGI.escape('https://resource2.com')}"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_grants].count == 1,
           "no grant has been created"

    oauth_grant = db[:oauth_grants].first

    assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{oauth_grant[:code]}",
           "was redirected instead to #{page.current_url}"
    assert oauth_grant[:resource] == "https://resource.com https://resource2.com"
  end
end
