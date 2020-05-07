# frozen_string_literal: true

require "test_helper"

class RodaOauthApplicationsTest < Minitest::Test
  include Capybara::DSL

  def test_oauth_applications_successful
    setup_application
    # List
    visit "/oauth-applications"
    assert_includes page.html, "No oauth applications yet!"
    # Create a new Application
    click_link "Register new Oauth Application"
    assert_includes page.html, "Register Oauth Application"
    fill_in 'name', :with=> "Foo App"
    fill_in 'description', :with=> "An app starting with Foo"
    fill_in 'homepage-url', :with=> "https://foobar.com"
    fill_in 'callback-url', :with=> "https://foobar.com/callback"
    check "user.read"
    check "user.write"
    click_button "Register"

    # Application page
    assert_equal page.find('#notice_flash').text, 'Your oauth application has been registered'
    assert_includes page.html, "Client ID: "
    assert_includes page.html, "Client Secret: "
    assert_includes page.html, "Scopes: "
    assert DB[:oauth_applications].count == 1
  end

  def test_oauth_applications_invalid_fields
  	setup_application
  	visit "/oauth-applications/new"
  	click_button "Register"
  	# must fill fields
  	assert_equal page.find('#error_flash').text, 'There was an error registering your oauth application'
    assert_includes page.html, "is not filled"

    # validate url
    fill_in 'name', :with=> "Foo App"
    fill_in 'description', :with=> "An app starting with Foo"
    fill_in 'homepage-url', :with=> "bla"
    fill_in 'callback-url', :with=> "bla"
    click_button "Register"
  	assert_equal page.find('#error_flash').text, 'There was an error registering your oauth application'
    assert_includes page.html, "Invalid URL"
  end

  private

  def setup_application
    rodauth do
      enable :oauth
      oauth_application_default_scope "user.read"
      oauth_application_scopes %w[user.read user.write]
      password_match? do |_password|
        true
      end
    end
    roda do |r|
      r.rodauth

      r.root do
        "Unauthorized"
      end

      rodauth.oauth_applications
      rodauth.oauth_authorize

      r.on "private" do
        r.get do
          "Authorized"
        end
      end
    end
  end
end
