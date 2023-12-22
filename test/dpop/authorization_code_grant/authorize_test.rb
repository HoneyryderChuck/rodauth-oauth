# frozen_string_literal: true

require "test_helper"

class RodauthOauthDPopAuthorizeTest < DPoPIntegration
  include Rack::Test::Methods

  def test_authorize_post_authorize
    dpop_key = OpenSSL::PKey::RSA.generate(2048)
    dpop_public_key = dpop_key.public_key
    jkt = generate_thumbprint(dpop_public_key)

    setup_application
    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&response_type=code&" \
          "scope=user.read+user.write&response_type=code&dpop_jkt=#{jkt}"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "user.read"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_grants].count == 1,
           "no grant has been created"

    oauth_grant = db[:oauth_grants].first

    assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{oauth_grant[:code]}",
           "was redirected instead to #{page.current_url}"

    assert oauth_grant[:dpop_jkt] == jkt

    header "DPoP", generate_dpop_proof(OpenSSL::PKey::RSA.generate(2048))
    post(
      "/token",
      client_id: oauth_application[:client_id],
      client_secret: "CLIENT_SECRET",
      grant_type: "authorization_code",
      code: oauth_grant[:code],
      redirect_uri: oauth_grant[:redirect_uri]
    )

    verify_response(400)
    assert json_body["error"] == "invalid_grant"

    @json_body = nil

    header "DPoP", generate_dpop_proof(dpop_key)
    post(
      "/token",
      client_id: oauth_application[:client_id],
      client_secret: "CLIENT_SECRET",
      grant_type: "authorization_code",
      code: oauth_grant[:code],
      redirect_uri: oauth_grant[:redirect_uri]
    )

    assert_equal 200, last_response.status
    verify_access_token(json_body["access_token"], oauth_grant, bound_dpop_key: dpop_public_key)
  end

  def test_authorize_post_authorize_with_pkce
    dpop_key = OpenSSL::PKey::RSA.generate(2048)
    dpop_public_key = dpop_key.public_key
    jkt = generate_thumbprint(dpop_public_key)

    setup_application(:oauth_pkce)
    login

    # show the authorization form
    visit "/authorize?code_challenge=#{PKCE_CHALLENGE}&code_challenge_method=S256&" \
          "client_id=#{oauth_application[:client_id]}&response_type=code&" \
          "scope=user.read+user.write&response_type=code&dpop_jkt=#{jkt}"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "user.read"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_grants].count == 1,
           "no grant has been created"

    oauth_grant = db[:oauth_grants].first
    assert oauth_grant[:code_challenge] == PKCE_CHALLENGE
    assert oauth_grant[:code_challenge_method] == "S256"

    assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{oauth_grant[:code]}",
           "was redirected instead to #{page.current_url}"

    assert oauth_grant[:dpop_jkt] == jkt

    header "DPoP", generate_dpop_proof(OpenSSL::PKey::RSA.generate(2048))
    post(
      "/token",
      client_id: oauth_application[:client_id],
      code_verifier: PKCE_VERIFIER,
      grant_type: "authorization_code",
      code: oauth_grant[:code],
      redirect_uri: oauth_grant[:redirect_uri]
    )

    verify_response(400)
    assert json_body["error"] == "invalid_grant"

    @json_body = nil

    header "DPoP", generate_dpop_proof(dpop_key)
    post(
      "/token",
      client_id: oauth_application[:client_id],
      code_verifier: PKCE_VERIFIER,
      grant_type: "authorization_code",
      code: oauth_grant[:code],
      redirect_uri: oauth_grant[:redirect_uri]
    )

    assert_equal 200, last_response.status
    verify_access_token(json_body["access_token"], oauth_grant, bound_dpop_key: dpop_public_key)
  end

  private

  def setup_application(*)
    rodauth do
      oauth_dpop_bound_access_tokens true
      oauth_response_mode "query"
    end
    super
  end
end
