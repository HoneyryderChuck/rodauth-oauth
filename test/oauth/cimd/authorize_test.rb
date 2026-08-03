# frozen_string_literal: true

require "test_helper"
require "webmock/minitest"

class RodauthOauthcimdAuthorizeTest < JWTIntegration
  include WebMock::API

  def test_cimd_authorize_non_url
    setup_application
    login

    # show the authorization form
    visit "/authorize?client_id=bang"
    assert_includes page.html, "Invalid or missing 'client_id'"
  end

  def test_cimd_authorize_invalid_client_id_url
    setup_application
    login

    visit "/authorize?client_id=http://localhost"
    # show the authorization form
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    assert_includes page.html, "Invalid or missing 'client_id'"
  end

  def test_cimd_authorize_post_authorize
    setup_application
    stub_request(:get, "https://cimd-host/cimd-client")
      .to_return_json(status: 200, body: {
                        "client_id" => "https://cimd-host/cimd-client",
                        "redirect_uris" => %w[
                          https://example.com/callback
                        ],
                        "token_endpoint_auth_method" => "private_key_jwt",
                        "client_name" => "This client name",
                        "client_uri" => "https://foobar.com",
                        "logo_uri" => "https://foobar.com/logo.png",
                        "scope" => "user.read user.write",
                        "contacts" => %w[emp@mail.com],
                        "tos_uri" => "https://foobar.com/tos",
                        "policy_uri" => "https://foobar.com/policy",
                        "jwks_uri" => "https://foobar.com/jwks"
                      })
    login

    # show the authorization form
    visit "/authorize?client_id=https://cimd-host/cimd-client&response_type=code&scope=user.read+user.write&response_type=code"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"

    check "user.read"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_grants].one?,
           "no grant has been created"

    oauth_grant = db[:oauth_grants].first

    assert page.current_url == "https://example.com/callback?code=#{oauth_grant[:code]}",
           "was redirected instead to #{page.current_url}"
  end

  private

  def setup_application(*)
    rodauth do
      oauth_response_mode "query"
    end
    super
  end

  def oauth_feature
    %i[oauth_authorization_code_grant oauth_jwt_bearer_grant oauth_client_id_metadata_document]
  end
end
