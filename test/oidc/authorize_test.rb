# frozen_string_literal: true

require "test_helper"

class RodauthOauthOIDCAuthorizeTest < OIDCIntegration
  def test_oidc_authorize_with_request_uri
    setup_application
    login

    visit "/authorize?request_uri=https://request-uri.com/yadayada"
    assert page.current_url.include?("?error=request_uri_not_supported"),
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_authorize_with_invalid_request
    setup_application
    login

    visit "/authorize?request=eyIknowthisisbad.yes.yes&client_id=#{oauth_application[:client_id]}"
    assert page.current_url.include?("?error=invalid_request_object"),
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_authorize_unverifiable_request
    setup_application
    login

    rsa_private = OpenSSL::PKey::RSA.generate(2048)
    rsa_public = rsa_private.public_key
    rodauth do
      oauth_jwt_key rsa_private
      oauth_jwt_public_key rsa_public
      oauth_jwt_algorithm "RS256"
    end

    signed_request = generate_signed_request(oauth_application)

    visit "/authorize?request=#{signed_request}&client_id=#{oauth_application[:client_id]}"
    assert page.current_url.include?("?error=invalid_request_object"),
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_authorize_with_signed_request
    setup_application
    login

    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key

    application = oauth_application(jws_jwk: JSON.dump(JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256")))

    signed_request = generate_signed_request(application, signing_key: jws_key)

    visit "/authorize?request=#{signed_request}&client_id=#{application[:client_id]}"

    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
  end

  def test_oidc_authorize_with_signed_encrypted_request
    jwe_key = OpenSSL::PKey::RSA.new(2048)
    jwe_public_key = jwe_key.public_key
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key

    rodauth do
      oauth_jwt_jwe_key jwe_key
      oauth_jwt_jwe_algorithm "RSA-OAEP"
      oauth_jwt_jwe_encryption_method "A128CBC-HS256"
    end
    setup_application
    login

    application = oauth_application(jws_jwk: JSON.dump(JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256")))

    signed_request = generate_signed_request(application, signing_key: jws_key, encryption_key: jwe_public_key)

    visit "/authorize?request=#{signed_request}&client_id=#{application[:client_id]}"

    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
  end

  def test_oidc_authorize_post_authorize_with_nonce
    setup_application
    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&nonce=NONCE"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_grants].count == 1,
           "no grant has been created"

    oauth_grant = db[:oauth_grants].first
    assert oauth_grant[:nonce] == "NONCE"

    assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{oauth_grant[:code]}",
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_authorize_post_authorize_no_implicit_grant
    setup_application
    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=token"

    assert page.current_url.include?("?error=invalid_request"),
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_authorize_post_authorize_with_implicit_grant
    rodauth do
      oauth_jwt_key "SECRET"
      oauth_jwt_algorithm "HS256"
      use_oauth_implicit_grant_type? true
    end
    setup_application

    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=token"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_tokens].count == 1,
           "no token has been created"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#access_token=([^&]+)&token_type=bearer&expires_in=3600/,
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_authorize_post_authorize_with_id_token_response_type
    rodauth do
      oauth_jwt_key "SECRET"
      oauth_jwt_algorithm "HS256"
      use_oauth_implicit_grant_type? true
    end
    setup_application
    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=id_token"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_tokens].count == 1,
           "no token has been created"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#token_type=bearer&expires_in=3600&id_token=([^&]+)/,
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_authorize_post_authorize_with_none_response_type
    setup_application
    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=none"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"

    # submit authorization request
    click_button "Authorize"

    assert page.current_url == oauth_application[:redirect_uri],
           "was redirected instead to #{page.current_url}"
  end

  # Multiple Response Types

  def test_oidc_authorize_post_authorize_with_code_token_response_type
    rodauth do
      oauth_jwt_key "SECRET"
      oauth_jwt_algorithm "HS256"
      use_oauth_implicit_grant_type? true
    end
    setup_application
    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=code+token"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_grants].count == 1,
           "no grant has been created"

    assert db[:oauth_tokens].count == 1,
           "no token has been created"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#code=([^&]+)&access_token=([^&]+)&token_type=bearer&expires_in=3600/,
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_authorize_post_authorize_with_code_id_token_response_type
    rodauth do
      oauth_jwt_key "SECRET"
      oauth_jwt_algorithm "HS256"
      use_oauth_implicit_grant_type? true
    end
    setup_application
    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=code+id_token"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_grants].count == 1,
           "no grant has been created"

    assert db[:oauth_tokens].count == 1,
           "no token has been created"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#code=([^&]+)&token_type=bearer&expires_in=3600&id_token=([^&]+)/,
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_authorize_post_authorize_with_id_token_token_response_type
    rodauth do
      oauth_jwt_key "SECRET"
      oauth_jwt_algorithm "HS256"
      use_oauth_implicit_grant_type? true
    end
    setup_application
    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=id_token+token"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"

    # submit authorization request
    click_button "Authorize"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#token_type=bearer&|
                                expires_in=3600&id_token=([^&]+)&access_token=([^&]+)/,
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_authorize_post_authorize_with_code_id_token_token_response_type
    rodauth do
      oauth_jwt_key "SECRET"
      oauth_jwt_algorithm "HS256"
      use_oauth_implicit_grant_type? true
    end
    setup_application
    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=code+id_token+token"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_grants].count == 1,
           "no grant has been created"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#code=([^&]+)&|
                                token_type=bearer&expires_in=3600&id_token=([^&]+)&access_token=([^&]+)/,
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_authorize_post_authorize_prompt_none
    setup_application

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&" \
          "prompt=none"
    assert page.current_url.include?("?error=login_required"),
           "was redirected instead to #{page.current_url}"

    login

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&" \
          "prompt=none"
    assert page.current_url.include?("?error=consent_required"),
           "was redirected instead to #{page.current_url}"

    # OLD grant
    oauth_grant(access_type: "online", expires_in: Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, seconds: 60))

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&" \
          "prompt=none"

    assert db[:oauth_grants].count == 2,
           "no new grant has been created"

    new_grant = db[:oauth_grants].order(:id).last

    assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{new_grant[:code]}",
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_authorize_post_authorize_prompt_login
    setup_application

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&" \
          "prompt=login"
    assert page.current_path.include?("/login"),
           "was redirected instead to #{page.current_url}"

    login(visit: false)

    assert page.current_url.end_with?("/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&prompt=login"),
           "was redirected instead to #{page.current_url}"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    # submit authorization request
    click_button "Authorize"

    new_grant = db[:oauth_grants].order(:id).last
    assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{new_grant[:code]}",
           "was redirected instead to #{page.current_url}"
  end

  if RUBY_VERSION > "2.4"
    def test_oidc_authorize_post_authorize_prompt_select_account_with_login
      hash = BCrypt::Password.create("0123456789", cost: BCrypt::Engine::MIN_COST)
      db[:accounts].insert(email: "foo2@example.com", status_id: 2, ph: hash)

      setup_application(:select_account)

      login
      logout
      login(login: "foo2@example.com")
      logout

      visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&" \
            "prompt=select-account"

      # I should now select an account
      assert page.current_path.include?("/select-account"),
             "was redirected instead to #{page.current_url}"
      click_button("foo@example.com")
      assert page.current_path.include?("/login"),
             "was redirected instead to #{page.current_url}"

      # I should login now
      fill_in "Password", with: "0123456789"
      click_button "Login"

      assert page.current_url.end_with?("/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&prompt=select-account"),
             "was redirected instead to #{page.current_url}"
      assert page.current_path == "/authorize",
             "was redirected instead to #{page.current_path}"
      # submit authorization request
      click_button "Authorize"

      new_grant = db[:oauth_grants].order(:id).last
      assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{new_grant[:code]}",
             "was redirected instead to #{page.current_url}"
    end
  end

  def test_oidc_authorize_post_authorize_prompt_login_with_reauthentication
    setup_application
    login

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&" \
          "prompt=login"
    assert page.current_path.start_with?("/login"),
           "was redirected instead to #{page.current_url}"

    login(visit: false)

    assert page.current_url.end_with?("/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&prompt=login"),
           "was redirected instead to #{page.current_url}"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    # submit authorization request
    click_button "Authorize"

    new_grant = db[:oauth_grants].order(:id).last
    assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{new_grant[:code]}",
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_authorize_post_authorize_prompt_consent
    setup_application
    login

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&" \
          "prompt=consent"
    assert page.current_url.include?("?error=consent_required"),
           "was redirected instead to #{page.current_url}"
  end

  # TODO: if rodauth ever supports definition of multiple accounts
  # def test_oidc_authorize_post_authorize_prompt_select_account
  # end

  private

  def setup_application(*)
    rodauth do
      oauth_applications_jws_jwk_column :jws_jwk
    end
    super
  end

  def generate_signed_request(application, signing_key: OpenSSL::PKey::RSA.generate(2048), encryption_key: nil)
    claims = {
      iss: "http://www.example.com",
      aud: "http://www.example.com",
      response_type: "code",
      client_id: application[:client_id],
      redirect_uri: application[:redirect_uri],
      scope: application[:scopes],
      state: "ABCDEF"
    }

    headers = {}

    jwk = JWT::JWK.new(signing_key)
    headers[:kid] = jwk.kid

    signing_key = jwk.keypair

    token = JWT.encode(claims, signing_key, "RS256", headers)

    if encryption_key
      params = {
        enc: "A128CBC-HS256",
        alg: "RSA-OAEP"
      }
      token = JWE.encrypt(token, encryption_key, **params)
    end

    token
  end
end
