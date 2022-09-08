# frozen_string_literal: true

require "test_helper"

class RodauthGrantsTest < RodaIntegration
  def test_my_grants
    setup_application
    login

    # List empty
    visit "/oauth-grants"
    assert_includes page.html, "No oauth grants yet!"

    oauth_grant = set_oauth_grant_with_token

    # List as owner
    visit "/oauth-grants"
    assert_includes page.html, oauth_application[:name]
    assert_includes page.html, oauth_grant[:token]
    assert_includes page.html, oauth_grant[:refresh_token]
    assert_includes page.html, oauth_grant[:expires_in].to_s

    # List as non-owner
    logout
    login login: "bar@example.com", pass: "0123456789"
    visit "/oauth-grants"
    assert_includes page.html, "No oauth grants yet!"

    # Revoke
    logout
    login
    visit "/oauth-grants"
    click_button "Revoke"
    assert_equal page.find("#notice").text, "The oauth grant has been revoked"
    assert_includes page.html, "No oauth grants yet!"

    assert db[:oauth_grants].where(revoked_at: nil).count.zero?
  end

  unless ENV.key?("ONLY_ONE_TOKEN")
    def test_oauth_grants_pages
      setup_application
      login

      6.times do |i|
        set_oauth_grant_with_token(token: "TOKEN#{i}", refresh_token: "REFRESH_TOKEN#{i}")
      end

      # List
      visit "/oauth-grants"

      assert_includes page.html, "TOKEN0"

      visit "/oauth-grants?per_page=5"
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

  def oauth_feature
    %i[oauth_application_management oauth_grant_management]
  end

  def setup_application(*args)
    super(*args, &:oauth_grants)
  end
end
