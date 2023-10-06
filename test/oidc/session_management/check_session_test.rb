# frozen_string_literal: true

require "test_helper"

class RodauthOauthOIDCSessionManagementCheckSessionTest < OIDCIntegration
  def test_oidc_check_session_iframe
    setup_application
    login
    visit "/check-session"

    assert_includes page.html, "<!DOCTYPE html>\n<html>"
    assert_includes page.html, "function receiveMessage(e)"
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
