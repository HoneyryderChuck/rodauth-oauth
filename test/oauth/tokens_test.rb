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
    assert_includes page.html, oauth_application[:name]
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

  unless ENV.key?("ONLY_ONE_TOKEN")
    def test_oauth_tokens_pages
      setup_application
      login

      6.times do |i|
        set_oauth_token(token: "TOKEN#{i}", refresh_token: "REFRESH_TOKEN#{i}")
      end

      # List
      visit "/oauth-tokens"

      assert_includes page.html, "TOKEN0"

      visit "/oauth-tokens?per_page=5"
      assert_includes page.html, "TOKEN5"
      assert_includes page.html, "TOKEN4"
      assert_includes page.html, "TOKEN3"
      assert_includes page.html, "TOKEN2"
      assert_includes page.html, "TOKEN1"
      refute_includes page.html, "TOKEN0"

      click_link "Next"
      refute_includes page.html, "TOKEN5"
      refute_includes page.html, "TOKEN4"
      refute_includes page.html, "TOKEN3"
      refute_includes page.html, "TOKEN2"
      refute_includes page.html, "TOKEN1"
      assert_includes page.html, "TOKEN0"
      click_link "Previous"

      assert_includes page.html, "TOKEN5"
      assert_includes page.html, "TOKEN4"
      assert_includes page.html, "TOKEN3"
      assert_includes page.html, "TOKEN2"
      assert_includes page.html, "TOKEN1"
      refute_includes page.html, "TOKEN0"
    end
  end

  private

  def setup_application
    super(&:oauth_tokens)
  end
end
