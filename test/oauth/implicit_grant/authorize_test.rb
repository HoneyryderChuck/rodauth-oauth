# frozen_string_literal: true

require "test_helper"

class RodauthOauthImplicitGrantAuthorizeTest < RodaIntegration
  def test_authorize_post_authorize_no_implicit_grant
    setup_application
    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=user.read+user.write&response_type=token"

    assert page.current_url.include?("?error=invalid_request"),
           "was redirected instead to #{page.current_url}"
  end

  def test_authorize_post_authorize_with_implicit_grant
    rodauth do
      use_oauth_implicit_grant_type? true
    end
    setup_application

    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&response_type=token&state=STATE"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_tokens].count == 1,
           "no token has been created"

    oauth_token = db[:oauth_tokens].first

    assert page.current_url == "#{oauth_application[:redirect_uri]}#access_token=#{oauth_token[:token]}&" \
                               "token_type=bearer&expires_in=3600&state=STATE",
           "was redirected instead to #{page.current_url}"
  end

  private

  def oauth_feature
    :oauth_implicit_grant
  end
end
