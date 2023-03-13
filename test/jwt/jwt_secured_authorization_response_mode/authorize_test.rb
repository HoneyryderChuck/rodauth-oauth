# frozen_string_literal: true

require "test_helper"
require "webmock/minitest"

class RodauthOauthJwtSecuredAuthorizationResponseModeAuthorizeTest < JWTIntegration
  include WebMock::API

  %w[query.jwt jwt].each do |mode|
    define_method :"test_jarm_authorize_post_authorize_with_code_and_response_mode_#{mode}" do
      setup_application
      login

      jws_key = OpenSSL::PKey::RSA.generate(2048)
      jws_public_key = jws_key.public_key

      application = oauth_application(jwks: JSON.dump([JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256")]))

      # show the authorization form
      visit "/authorize?client_id=#{application[:client_id]}&response_type=code&response_mode=query.jwt&state=STATE"
      assert page.current_path == "/authorize",
             "was redirected instead to #{page.current_path}"
      check "user.read"
      click_button "Authorize"

      assert page.current_url =~ /#{oauth_application[:redirect_uri]}?response=([^&]+)/,
             "was redirected instead to #{page.current_url}"

      claims = verify_jwt_response(Regexp.last_match(1), application, jws_public_key, "RS256")

      assert claims.key?("state")
      assert claims["state"] == "STATE"

      assert db[:oauth_grants].count == 1,
             "no grant has been created"

      oauth_grant = db[:oauth_grants].first

      assert claims.key?("code")
      assert oauth_grant[:code] == claims["code"]
    end

    define_method :"test_jarm_authorize_post_authorize_with_code_and_jwe_and_response_mode_#{mode}" do
      setup_application
      login

      jws_key = OpenSSL::PKey::RSA.generate(2048)
      jws_public_key = jws_key.public_key
      jwe_key = OpenSSL::PKey::RSA.new(2048)
      jwe_public_key = jwe_key.public_key

      application = oauth_application(jwks: JSON.dump([
                                                        JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256"),
                                                        JWT::JWK.new(jwe_public_key).export.merge(use: "enc", alg: "RSA-OAEP",
                                                                                                  enc: "A128CBC-HS256")
                                                      ]),
                                      authorization_signed_response_alg: "RS256",
                                      authorization_encrypted_response_alg: "RSA-OAEP",
                                      authorization_encrypted_response_enc: "A256CBC-HS512")

      # show the authorization form
      visit "/authorize?client_id=#{application[:client_id]}&response_type=code&response_mode=query.jwt&state=STATE"
      assert page.current_path == "/authorize",
             "was redirected instead to #{page.current_path}"
      check "user.read"
      click_button "Authorize"

      assert page.current_url =~ /#{oauth_application[:redirect_uri]}?response=([^&]+)/,
             "was redirected instead to #{page.current_url}"

      token = Regexp.last_match(1)
      token = JWE.decrypt(token, jwe_key)
      claims = verify_jwt_response(token, application, jws_public_key, "RS256")

      assert claims.key?("state")
      assert claims["state"] == "STATE"

      assert db[:oauth_grants].count == 1,
             "no grant has been created"

      oauth_grant = db[:oauth_grants].first

      assert claims.key?("code")
      assert oauth_grant[:code] == claims["code"]
    end
  end

  def test_jarm_authorize_post_authorize_with_code_with_fragment_jwt_mode
    setup_application
    login

    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key

    application = oauth_application(jwks: JSON.dump([JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256")]))

    # show the authorization form
    visit "/authorize?client_id=#{application[:client_id]}&response_type=code&response_mode=fragment.jwt&state=STATE"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "user.read"
    click_button "Authorize"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#response=([^&]+)/,
           "was redirected instead to #{page.current_url}"

    claims = verify_jwt_response(Regexp.last_match(1), application, jws_public_key, "RS256")

    assert claims.key?("error")
    assert claims["error"] == "invalid_request"
    assert claims.key?("state")
    assert claims["state"] == "STATE"
  end

  def test_jarm_authorize_post_authorize_with_code_with_fragment_jwt_mode_encrypted
    setup_application
    login

    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    jwe_key = OpenSSL::PKey::RSA.new(2048)
    jwe_public_key = jwe_key.public_key

    application = oauth_application(jwks: JSON.dump([
                                                      JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256"),
                                                      JWT::JWK.new(jwe_public_key).export.merge(use: "enc", alg: "RSA-OAEP",
                                                                                                enc: "A128CBC-HS256")
                                                    ]),
                                    authorization_signed_response_alg: "RS256",
                                    authorization_encrypted_response_alg: "RSA-OAEP",
                                    authorization_encrypted_response_enc: "A256CBC-HS512")

    # show the authorization form
    visit "/authorize?client_id=#{application[:client_id]}&response_type=code&response_mode=fragment.jwt&state=STATE"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "user.read"
    click_button "Authorize"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#response=([^&]+)/,
           "was redirected instead to #{page.current_url}"

    claims = verify_jwt_response(Regexp.last_match(1), application, jws_public_key, "RS256")

    assert claims.key?("error")
    assert claims["error"] == "invalid_request"
    assert claims.key?("state")
    assert claims["state"] == "STATE"
  end

  %w[fragment.jwt jwt].each do |mode|
    define_method :"test_jarm_authorize_post_authorize_with_token_and_response_mode_#{mode}" do
      setup_application
      login

      jws_key = OpenSSL::PKey::RSA.generate(2048)
      jws_public_key = jws_key.public_key

      application = oauth_application(jwks: JSON.dump([JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256")]))

      # show the authorization form
      visit "/authorize?client_id=#{application[:client_id]}&response_type=token&response_mode=fragment.jwt&state=STATE"
      assert page.current_path == "/authorize",
             "was redirected instead to #{page.current_path}"
      check "user.read"
      click_button "Authorize"

      assert page.current_url =~ /#{oauth_application[:redirect_uri]}#response=([^&]+)/,
             "was redirected instead to #{page.current_url}"

      claims = verify_jwt_response(Regexp.last_match(1), application, jws_public_key, "RS256")

      assert claims.key?("state")
      assert claims["state"] == "STATE"

      assert db[:oauth_grants].count == 1,
             "no grant has been created"

      oauth_grant = db[:oauth_grants].first

      assert claims.key?("access_token")
      verify_access_token(claims["access_token"], oauth_grant, signing_key: jws_public_key, signing_algo: "RS256",
                                                               audience: application[:client_id])
      assert claims.key?("token_type")
      assert claims["token_type"] == "Bearer"
      assert claims.key?("state")
      assert claims["state"] == "STATE"
      assert claims.key?("expires_in")
      assert claims.key?("scope")
      assert claims["scope"] == application[:scope]
    end
  end

  def test_jarm_authorize_post_authorize_with_token_with_query_jwt_encrypted
    setup_application
    login

    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    jwe_key = OpenSSL::PKey::RSA.new(2048)
    jwe_public_key = jwe_key.public_key

    application = oauth_application(jwks: JSON.dump([
                                                      JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256"),
                                                      JWT::JWK.new(jwe_public_key).export.merge(use: "enc", alg: "RSA-OAEP",
                                                                                                enc: "A128CBC-HS256")
                                                    ]),
                                    authorization_signed_response_alg: "RS256",
                                    authorization_encrypted_response_alg: "RSA-OAEP",
                                    authorization_encrypted_response_enc: "A256CBC-HS512")

    # show the authorization form
    visit "/authorize?client_id=#{application[:client_id]}&response_type=token&response_mode=query.jwt&state=STATE"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "user.read"
    click_button "Authorize"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#response=([^&]+)/,
           "was redirected instead to #{page.current_url}"

    claims = verify_jwt_response(Regexp.last_match(1), application, jws_public_key, "RS256")

    assert claims.key?("state")
    assert claims["state"] == "STATE"

    assert db[:oauth_grants].count == 1,
           "no grant has been created"

    oauth_grant = db[:oauth_grants].first

    assert claims.key?("access_token")
    verify_access_token(claims["access_token"], oauth_grant, signing_key: jws_public_key, signing_algo: "RS256",
                                                             audience: application[:client_id])
    assert claims.key?("token_type")
    assert claims["token_type"] == "Bearer"
    assert claims.key?("state")
    assert claims["state"] == "STATE"
    assert claims.key?("expires_in")
    assert claims.key?("scope")
    assert claims["scope"] == application[:scope]
  end

  def test_jarm_authorize_post_authorize_with_code_and_response_mode_form_post_jwt
    setup_application
    login

    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key

    application = oauth_application(jwks: JSON.dump([JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256")]))

    # show the authorization form
    visit "/authorize?client_id=#{application[:client_id]}&response_type=code&response_mode=form_post.jwt&state=STATE"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "user.read"
    click_button "Authorize"

    assert_match(/name="response" value="([^&]+)"/, page.html)

    claims = verify_jwt_response(Regexp.last_match(1), application, jws_public_key, "RS256")

    assert claims.key?("state")
    assert claims["state"] == "STATE"

    assert db[:oauth_grants].count == 1,
           "no grant has been created"

    oauth_grant = db[:oauth_grants].first

    assert claims.key?("code")
    assert oauth_grant[:code] == claims["code"]

    assert page.has_button?("Back to Client Application")
    click_button("Back to Client Application")

    assert page.current_url == oauth_application[:redirect_uri].to_s,
           "was redirected instead to #{page.current_url}"
  end

  private

  def setup_application(*)
    rodauth do
      oauth_applications_jwks_column :jwks
    end
    super
  end

  def oauth_feature
    %i[oauth_authorization_code_grant implicit_grant oauth_jwt_secured_authorization_response_mode]
  end

  def verify_jwt_response(jwt, oauth_application, signing_key, signing_algo)
    claims, headers = JWT.decode(jwt, signing_key, true, algorithms: [signing_algo])
    assert headers["alg"] == signing_algo

    assert claims.key?("iss")
    assert claims["iss"] == example_origin
    assert claims.key?("aud")
    assert claims["aud"] == oauth_application[:client_id]
    assert claims.key?("exp")

    claims
  end
end
