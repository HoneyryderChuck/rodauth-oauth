# frozen_string_literal: true

require "test_helper"

class RodaOauthTokensTest < RodaIntegration
  def test_oauth_tokens
    setup_application
    login
    # List
    visit "/oauth-applications/#{oauth_application[:id]}/oauth-tokens"
    assert_includes page.html, "No oauth tokens yet!"

    oauth_token
    visit "/oauth-applications/#{oauth_application[:id]}/oauth-tokens"

    assert_includes page.html, oauth_token[:token]
    assert_includes page.html, oauth_token[:refresh_token]
    assert_includes page.html, oauth_token[:expires_in].to_s
    assert_includes page.html, "value=\"Revoke"

    # Revokes token
    click_button "Revoke"
    assert_equal page.find("#notice_flash").text, "The oauth token has been revoked"
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
