# frozen_string_literal: true

require "test_helper"

class RodauthTokensTest < RodaIntegration
  def test_my_tokens
    setup_application
    login

    # List empty
    visit "/oauth-tokens"
    assert_includes page.html, "No oauth tokens yet!"

    oauth_token

    # List as owner
    visit "/oauth-tokens"
    assert_includes page.html, oauth_token[:token]
    assert_includes page.html, oauth_token[:refresh_token]
    assert_includes page.html, oauth_token[:expires_in].to_s

    # List as non-owner
    logout
    login login: "bar@example.com", pass: "0123456789"
    visit "/oauth-tokens"
    assert_includes page.html, "No oauth tokens yet!"

    # Revoke
    logout
    login
    visit "/oauth-tokens"
    click_button "Revoke"
    assert_equal page.find("#notice").text, "The oauth token has been revoked"
    assert_includes page.html, "No oauth tokens yet!"

    assert db[:oauth_tokens].where(revoked_at: nil).count.zero?
  end

  private

  def setup_application
    super(&:oauth_tokens)
  end
end
