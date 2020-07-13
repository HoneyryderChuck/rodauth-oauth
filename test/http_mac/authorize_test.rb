# frozen_string_literal: true

require "test_helper"

class RodauthOAuthHTTPMacAuthorizeTest < HTTPMacIntegration
  def test_http_mac_authorize_post_authorize_with_implicit_grant
    rodauth do
      use_oauth_implicit_grant_type? true
    end
    setup_application

    login

    # show the authorization form
    visit "/oauth-authorize?client_id=#{oauth_application[:client_id]}&response_type=token"
    assert page.current_path == "/oauth-authorize",
           "was redirected instead to #{page.current_path}"

    # submit authorization request
    click_button "Authorize"

    assert db[:http_mac_oauth_tokens].count == 1,
           "no token has been created"

    oauth_token = db[:http_mac_oauth_tokens].first

    assert page.current_url == "#{oauth_application[:redirect_uri]}?#access_token=#{oauth_token[:token]}&" \
                             "token_type=mac&expires_in=3600&mac_key=#{oauth_token[:mac_key]}&" \
                             "mac_algorithm=hmac-sha-256",
           "was redirected instead to #{page.current_url}"
  end
end
