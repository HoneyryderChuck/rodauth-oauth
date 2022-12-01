# frozen_string_literal: true

require "test_helper"

class RodauthOauthImplicitGrantAuthorizeTest < RodaIntegration
  def test_authorize_post_authorize_with_implicit_grant
    setup_application(:oauth_implicit_grant)

    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&response_type=token&state=STATE"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "user.read"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_grants].count == 1,
           "no token has been created"

    oauth_grant = db[:oauth_grants].first

    assert page.current_url == "#{oauth_application[:redirect_uri]}#access_token=#{oauth_grant[:token]}&" \
                               "token_type=bearer&expires_in=3600&state=STATE",
           "was redirected instead to #{page.current_url}"
  end

  private

  def oauth_feature
    :oauth_implicit_grant
  end

  def default_grant_type
    "implicit"
  end
end
