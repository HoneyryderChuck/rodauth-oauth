# frozen_string_literal: true

require "test_helper"

class RodaOauthApplicationsTest < RailsIntegrationTest
  def test_oauth_applications_successful
    login
    # List
    visit "/oauth-applications"
    assert_includes page.html, "No oauth applications yet!"
    # Create a new Application
    click_link "Register new Oauth Application"
    assert_includes page.html, "Register Oauth Application"
    fill_in "name", with: "Foo App"
    fill_in "description", with: "An app starting with Foo"
    fill_in "homepage_url", with: "https://foobar.com"
    fill_in "redirect_uri", with: "https://foobar.com/callback"
    check "user.read"
    check "user.write"
    click_button "Register"

    # Application page
    assert_equal page.find("#notice").text, "Your oauth application has been registered"
    assert_includes page.html, "Client ID: "
    assert_includes page.html, "Client Secret: "
    assert_includes page.html, "Scopes: "
    assert DB[:oauth_applications].count == 1
  end

  def test_oauth_applications_invalid_fields
    setup_application
    login

    visit "/oauth-applications"
    click_link "New Oauth Application"
    click_button "Register"
    # must fill fields
    assert_equal page.find("#alert").text, "There was an error registering your oauth application"
    assert_includes page.html, "is not filled"

    # validate url
    fill_in "name", with: "Foo App"
    fill_in "description", with: "An app starting with Foo"
    fill_in "homepage_url", with: "bla"
    fill_in "redirect_uri", with: "bla"
    click_button "Register"
    assert_equal page.find("#alert").text, "There was an error registering your oauth application"
    assert_includes page.html, "Invalid URL"
  end
end
