# frozen_string_literal: true

require "test_helper"

class RodauthOauthOIDCSessionManagementAuthorizeTest < OIDCIntegration
  def test_oidc_authorize_get_authorize_invalid_scope
    setup_application
    login
    visit "/authorize?client_id=#{oauth_application[:client_id]}&" \
          "response_type=code&" \
          "redirect_uri=#{oauth_application[:redirect_uri]}&" \
          "scope=marvel"
    assert page.current_url.include?("?error=invalid_scope"),
           "was redirected instead to #{page.current_url}"

    assert page.current_url.include?("session_state="),
           "no session_state in #{page.current_url}"
  end

  def test_oidc_authorize_post_authorize
    setup_application
    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&response_type=code"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"

    default_user_agent_state = page.driver.request.env["rack.request.cookie_hash"]["_rodauth_oauth_user_agent_state"]
    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_grants].one?,
           "no grant has been created"

    oauth_grant = db[:oauth_grants].first

    session_id = [
      oauth_application[:client_id],
      "https://example.com",
      default_user_agent_state,
      "SECRET"
    ].join(" ")

    session_state = [Digest::SHA256.hexdigest(session_id), "SECRET"].join(".")
    assert "#{oauth_application[:redirect_uri]}?code=#{oauth_grant[:code]}&session_state=#{session_state}" == page.current_url,
           "was redirected instead to #{page.current_url}"
  end

  private

  def oauth_feature
    %i[oidc oidc_session_management]
  end

  def setup_application(*)
    rodauth do
      oauth_jwt_keys("RS256" => OpenSSL::PKey::RSA.generate(2048))
      oauth_applications_jwks_column :jwks
      oauth_response_mode "query"
      oauth_oidc_session_management_salt "SECRET"
    end
    super
  end
end
