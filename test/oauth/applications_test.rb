# frozen_string_literal: true

require "test_helper"

class RodauthOauthApplicationsTest < RodaIntegration
  def test_oauth_applications_successful
    setup_application
    login
    # List
    visit "/oauth-applications"
    assert_includes page.html, "No oauth applications yet!"
    # Create a new Application
    click_link "Register new Oauth Application"
    assert_includes page.html, "Register Oauth Application"
    fill_in "name", with: "Foo App"
    fill_in "description", with: "An app starting with Foo"
    fill_in "homepage-url", with: "https://foobar.com"
    fill_in "redirect-uri1", with: "https://foobar.com/callback"
    fill_in "client-secret", with: "SECRET"
    check "user.read"
    check "user.write"
    click_button "Register"

    # Application page
    assert_equal page.find("#notice_flash").text, "Your oauth application has been registered"
    assert_includes page.html, "Client ID: "
    assert_includes page.html, "Scopes: "
    assert db[:oauth_applications].count == 1
  end

  def test_oauth_applications_multiple_redirect_uris
    setup_application
    login
    # List
    visit "/oauth-applications"
    assert_includes page.html, "No oauth applications yet!"
    # Create a new Application
    click_link "Register new Oauth Application"
    assert_includes page.html, "Register Oauth Application"
    fill_in "name", with: "Foo App"
    fill_in "description", with: "An app starting with Foo"
    fill_in "homepage-url", with: "https://foobar.com"
    fill_in "redirect-uri1", with: "https://foobar.com/callback"
    fill_in "redirect-uri2", with: "https://foobar.com/callback2"
    fill_in "client-secret", with: "SECRET"
    check "user.read"
    check "user.write"
    click_button "Register"

    # Application page
    assert_equal page.find("#notice_flash").text, "Your oauth application has been registered"
    assert_includes page.html, "Client ID: "
    assert_includes page.html, "Scopes: "
    assert db[:oauth_applications].count == 1
    assert db[:oauth_applications].first[:redirect_uri] == "https://foobar.com/callback https://foobar.com/callback2"
  end

  def test_oauth_applications_invalid_fields
    setup_application
    login

    visit "/oauth-applications/new"
    click_button "Register"
    # must fill fields
    assert_equal page.find("#error_flash").text, "There was an error registering your oauth application"
    assert_includes page.html, "is not filled"

    # validate url
    fill_in "name", with: "Foo App"
    fill_in "description", with: "An app starting with Foo"
    fill_in "homepage-url", with: "bla"
    fill_in "redirect-uri1", with: "bla"
    click_button "Register"
    assert_equal page.find("#error_flash").text, "There was an error registering your oauth application"
    assert_includes page.html, "Invalid URL"
  end

  private

  def setup_application
    super(&:oauth_applications)
  end
end
