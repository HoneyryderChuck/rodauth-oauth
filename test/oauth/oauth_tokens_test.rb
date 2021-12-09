# frozen_string_literal: true

require "test_helper"

class RodauthOauthTokensTest < RodaIntegration
  def test_oauth_tokens
    setup_application
    login
    # List
    visit "/oauth-applications/#{oauth_application[:id]}/oauth-tokens"
    assert_includes page.html, "No oauth tokens yet!"

    oauth_token

    logout
    login login: "bar@example.com", pass: "0123456789"
    visit "/oauth-applications/#{oauth_application[:id]}"

    assert_equal page.status_code, 404

    logout
    login
    visit "/oauth-applications/#{oauth_application[:id]}/oauth-tokens"

    assert_includes page.html, oauth_token[:token]
    assert_includes page.html, oauth_token[:refresh_token]
    assert_includes page.html, oauth_token[:expires_in].to_s
    assert_includes page.html, "value=\"Revoke"

    visit "/oauth-applications/#{oauth_application[:id]}/oauth-tokens"

    click_button "Revoke"
    assert_equal page.find("#notice").text, "The oauth token has been revoked"
    assert_includes page.html, oauth_token[:token]
    assert_includes page.html, oauth_token[:refresh_token]
    assert_includes page.html, oauth_token[:expires_in].to_s
    refute_includes page.html, "value=\"Revoke"

    assert db[:oauth_tokens].where(revoked_at: nil).count.zero?
  end

  private

  def setup_application
    super(&:oauth_applications)
  end
end
