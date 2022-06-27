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

    application = oauth_application(jwks: JSON.dump([JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256")]))

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

    application = oauth_application(jwks: JSON.dump([JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256")]))

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
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_key jws_key
      oauth_jwt_public_key jws_public_key
      oauth_jwt_algorithm "RS256"
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
    verify_access_token(Regexp.last_match(1), db[:oauth_tokens].first, signing_key: jws_public_key, signing_algo: "RS256")
  end

  def test_oidc_authorize_post_authorize_with_id_token_response_type
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_key jws_key
      oauth_jwt_public_key jws_public_key
      oauth_jwt_algorithm "RS256"
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
    verify_id_token(Regexp.last_match(1), db[:oauth_tokens].first, signing_key: jws_public_key, signing_algo: "RS256")
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
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_key jws_key
      oauth_jwt_public_key jws_public_key
      oauth_jwt_algorithm "RS256"
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
    verify_access_token(Regexp.last_match(2), db[:oauth_tokens].first, signing_key: jws_public_key, signing_algo: "RS256")
  end

  def test_oidc_authorize_post_authorize_with_code_id_token_response_type
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_key jws_key
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

    verify_id_token(Regexp.last_match(2), db[:oauth_tokens].first, signing_key: jws_public_key, signing_algo: "RS256")
  end

  def test_oidc_authorize_post_authorize_with_id_token_token_response_type
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_key jws_key
      oauth_jwt_public_key jws_public_key
      oauth_jwt_algorithm "RS256"
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

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#token_type=bearer&expires_in=3600&id_token=([^&]+)&access_token=([^&]+)/,
           "was redirected instead to #{page.current_url}"
    verify_id_token(Regexp.last_match(1), db[:oauth_tokens].first, signing_key: jws_public_key, signing_algo: "RS256")
    verify_access_token(Regexp.last_match(2), db[:oauth_tokens].first, signing_key: jws_public_key, signing_algo: "RS256")
  end

  def test_oidc_authorize_post_authorize_with_code_id_token_token_response_type
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_key jws_key
      oauth_jwt_public_key jws_public_key
      oauth_jwt_algorithm "RS256"
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

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#code=([^&]+)&token_type=bearer&expires_in=3600&id_token=([^&]+)&access_token=([^&]+)/,
           "was redirected instead to #{page.current_url}"
    verify_id_token(Regexp.last_match(2), db[:oauth_tokens].first, signing_key: jws_public_key, signing_algo: "RS256")
    verify_access_token(Regexp.last_match(3), db[:oauth_tokens].first, signing_key: jws_public_key, signing_algo: "RS256")
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

  def test_oidc_authorize_post_authorize_with_id_token_signed_alg
    jws_rs256_key = OpenSSL::PKey::RSA.generate(2048)
    jws_rs512_key = OpenSSL::PKey::RSA.generate(2048)
    jws_rs512_public_key = jws_rs512_key.public_key
    rodauth do
      oauth_jwt_keys { { "RS256" => jws_rs256_key, "RS512" => jws_rs512_key } }
      oauth_jwt_algorithm "RS256"
      use_oauth_implicit_grant_type? true
    end
    setup_application
    login

    application = oauth_application(id_token_signed_response_alg: "RS512")

    # show the authorization form
    visit "/authorize?client_id=#{application[:client_id]}&scope=openid&response_type=id_token"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_tokens].count == 1,
           "no token has been created"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#token_type=bearer&expires_in=3600&id_token=([^&]+)/,
           "was redirected instead to #{page.current_url}"

    verify_id_token(Regexp.last_match(1), db[:oauth_tokens].first, signing_key: jws_rs512_public_key, signing_algo: "RS512")
  end

  def test_oidc_authorize_post_authorize_with_id_token_signed_encrypted_alg
    jwe_key = OpenSSL::PKey::RSA.new(2048)
    jwe_hs512_key = OpenSSL::PKey::RSA.new(2048)
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_key jws_key
      oauth_jwt_algorithm "RS256"
      use_oauth_implicit_grant_type? true
    end
    setup_application
    login

    application = oauth_application(
      jwks: JSON.dump([
                        JWT::JWK.new(jwe_key.public_key).export.merge(use: "enc", alg: "RSA-OAEP", enc: "A128CBC-HS256"),
                        JWT::JWK.new(jwe_hs512_key.public_key).export.merge(use: "enc", alg: "RSA-OAEP", enc: "A256CBC-HS512")
                      ]),
      id_token_signed_response_alg: "RS256",
      id_token_encrypted_response_alg: "RSA-OAEP",
      id_token_encrypted_response_enc: "A256CBC-HS512"
    )

    # show the authorization form
    visit "/authorize?client_id=#{application[:client_id]}&scope=openid&response_type=id_token"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_tokens].count == 1,
           "no token has been created"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#token_type=bearer&expires_in=3600&id_token=([^&]+)/,
           "was redirected instead to #{page.current_url}"

    verify_id_token(Regexp.last_match(1), db[:oauth_tokens].first, signing_key: jws_public_key, decryption_key: jwe_hs512_key,
                                                                   signing_algo: "RS256")
  end

  # minimum level of support required for this parameter is simply that its use must not result in an error.
  %w[page popup touch wap].each do |display|
    define_method :"test_oidc_authorize_post_authorize_display_#{display}" do
      setup_application
      login

      visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&" \
            "display=consent"
      assert page.current_path == "/authorize",
             "was redirected instead to #{page.current_path}"
    end
  end

  def test_oidc_authorize_post_authorize_ui_locales
    setup_application
    login

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&" \
          "ui_locales=pt de es"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    assert page.html.include?("Autorizar")
  end

  def test_oidc_authorize_post_authorize_claims_locales
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_key jws_key
      oauth_jwt_algorithm "RS256"
      use_oauth_implicit_grant_type? true
      get_additional_param do |account, claim, locale|
        case claim
        when :name
          locale == :pt ? "Tiago" : "James"
        else
          account[claim]
        end
      end
    end
    setup_application
    login

    oauth_application(scopes: "openid name")

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid name&" \
          "claims_locales=pt en&response_type=id_token"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"

    check "name"
    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_tokens].count == 1,
           "no token has been created"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#token_type=bearer&expires_in=3600&id_token=([^&]+)/,
           "was redirected instead to #{page.current_url}"

    verify_id_token(
      Regexp.last_match(1),
      db[:oauth_tokens].first,
      signing_key: jws_public_key,
      signing_algo: "RS256"
    ) do |claims|
      assert claims["name#pt"] == "Tiago"
      assert claims["name#en"] == "James"
    end
  end

  unless RUBY_ENGINE == "truffleruby"
    def test_oidc_authorize_post_authorize_max_age
      setup_application
      login

      visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&" \
            "max_age=3"
      assert page.current_path == "/authorize",
             "was redirected instead to #{page.current_path}"
      sleep(4)
      visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&" \
            "max_age=3"
      assert page.current_path == "/login",
             "was redirected instead to #{page.current_path}"
    end
  end

  def test_oidc_authorize_post_authorize_acr_value_phr_no_2factor
    setup_application
    login

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&" \
          "acr_values=phr"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
  end

  def test_oidc_authorize_post_authorize_acr_value_phr_with_2factor
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_key jws_key
      oauth_jwt_public_key jws_public_key
      enable :otp
      two_factor_auth_return_to_requested_location? true
      use_oauth_implicit_grant_type? true
    end
    setup_application
    login

    # Set OTP
    secret_length = (ROTP::Base32.respond_to?(:random_base32) ? ROTP::Base32.random_base32 : ROTP::Base32.random).length
    visit "/otp-setup"
    assert page.title == "Setup TOTP Authentication"
    assert page.html.include? "<svg"
    secret = page.html.match(/Secret: ([a-z2-7]{#{secret_length}})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in "Password", with: "0123456789"
    fill_in "Authentication Code", with: totp.now
    click_button "Setup TOTP Authentication"
    assert page.html.include? "TOTP authentication is now setup"
    assert page.current_path == "/"
    reset_otp_last_use

    logout
    login

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&&response_type=id_token&" \
          "acr_values=phr"
    assert page.current_path == "/otp-auth",
           "was redirected instead to #{page.current_path}"
    fill_in "Authentication Code", with: totp.now
    click_button "Authenticate Using TOTP"

    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    # submit authorization request
    click_button "Authorize"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#token_type=bearer&expires_in=3600&id_token=([^&]+)/,
           "was redirected instead to #{page.current_url}"
    verify_id_token(Regexp.last_match(1), db[:oauth_tokens].first, signing_key: jws_public_key, signing_algo: "RS256")
  end

  begin
    require "webauthn/fake_client"
  rescue LoadError
  else
    def test_oidc_authorize_post_authorize_acr_value_phrh_with_2factor_webauthn
      rodauth do
        enable :webauthn_login
        two_factor_auth_return_to_requested_location? true
        use_oauth_implicit_grant_type? true
        hmac_secret "12345678"
      end
      setup_application

      webauthn_client = WebAuthn::FakeClient.new("http://www.example.com")
      visit "/login"
      fill_in "Login", with: "foo@example.com"
      click_button "Login"
      fill_in "Password", with: "0123456789"
      click_button "Login"

      # Set OTP
      visit "/webauthn-setup"
      challenge = JSON.parse(page.find("#webauthn-setup-form")["data-credential-options"])["challenge"]
      fill_in "Password", with: "0123456789"
      fill_in "webauthn_setup", with: webauthn_client.create(challenge: challenge).to_json
      click_button "Setup WebAuthn Authentication"
      assert page.html.include? "WebAuthn authentication is now setup"
      assert page.current_path == "/"

      logout
      visit "/login"
      fill_in "Login", with: "foo@example.com"
      click_button "Login"
      fill_in "Password", with: "0123456789"
      click_button "Login"

      visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&" \
            "acr_values=phrh"
      assert page.current_path == "/webauthn-auth",
             "was redirected instead to #{page.current_path}"
      challenge = JSON.parse(page.find("#webauthn-auth-form")["data-credential-options"])["challenge"]
      fill_in "webauthn_auth", with: webauthn_client.get(challenge: challenge).to_json
      click_button "Authenticate Using WebAuthn"

      assert page.current_path == "/authorize",
             "was redirected instead to #{page.current_path}"
    end
  end

  private

  def setup_application(*)
    rodauth do
      oauth_jwt_key OpenSSL::PKey::RSA.generate(2048)
      oauth_jwt_algorithm "RS256"
      oauth_applications_jwks_column :jwks
    end
    super
  end

  def reset_otp_last_use
    db[:account_otp_keys].update(last_use: Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, seconds: 600))
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
