# frozen_string_literal: true

require "test_helper"

class RodauthApplicationGrantsTest < RodaIntegration
  def test_application_grants
    setup_application(&:load_oauth_application_management_routes)
    login
    # List
    visit "/oauth-applications/#{oauth_application[:id]}/oauth-grants"
    assert_includes page.html, "No oauth grants yet!"

    oauth_grant = set_oauth_grant_with_token

    logout
    login login: "bar@example.com", pass: "0123456789"
    visit "/oauth-applications/#{oauth_application[:id]}"

    assert_equal page.status_code, 404

    logout
    login
    visit "/oauth-applications/#{oauth_application[:id]}/oauth-grants"

    assert_includes page.html, oauth_grant[:token]
    assert_includes page.html, oauth_grant[:refresh_token]
    assert_includes page.html, oauth_grant[:expires_in].to_s
    assert_includes page.html, "value=\"Revoke"

    visit "/oauth-applications/#{oauth_application[:id]}/oauth-grants"

    click_button "Revoke"
    assert_equal page.find("#notice").text, "The oauth grant has been revoked"
    assert_includes page.html, oauth_grant[:token]
    assert_includes page.html, oauth_grant[:refresh_token]
    assert_includes page.html, oauth_grant[:expires_in].to_s
    refute_includes page.html, "value=\"Revoke"

    assert db[:oauth_grants].where(revoked_at: nil).count.zero?
  end

  private

  def oauth_feature
    %i[oauth_application_management oauth_grant_management]
  end
end
