# frozen_string_literal: true

require "test_helper"

class RodauthOauthOIDCAuthorizeTest < OIDCIntegration
  def test_oidc_authorize_post_authorize_with_nonce
    setup_application
    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&nonce=NONCE&response_type=code"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_grants].count == 1,
           "no grant has been created"

    oauth_grant = db[:oauth_grants].first
    assert oauth_grant[:nonce] == "NONCE"

    assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{oauth_grant[:code]}",
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_authorize_post_authorize_with_implicit_grant
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_keys("RS256" => jws_key)
      oauth_jwt_public_keys("RS256" => jws_public_key)
    end
    setup_application

    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=token"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"

    # submit authorization request
    click_button "Authorize"

    assert db[:oauth_grants].count == 1,
           "no token has been created"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#access_token=([^&]+)&token_type=bearer&expires_in=3600/,
           "was redirected instead to #{page.current_url}"
    verify_access_token(Regexp.last_match(1), db[:oauth_grants].first, signing_key: jws_public_key, signing_algo: "RS256")
  end

  def test_oidc_authorize_post_authorize_with_id_token_response_type
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_keys("RS256" => jws_key)
      oauth_jwt_public_keys("RS256" => jws_public_key)
    end
    setup_application
    login

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=id_token&state=STATE&nonce=NONCE&response_mode=query"
    assert current_url.include?("#error=invalid_request")

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=id_token&state=STATE&nonce=NONCE"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"

    # submit authorization request
    click_button "Authorize"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#id_token=([^&]+)&state=STATE/,
           "was redirected instead to #{page.current_url}"

    assert db[:oauth_grants].count.zero?,
           "a grant has been created"
    verify_id_token(Regexp.last_match(1), db[:oauth_grants].first, signing_key: jws_public_key, signing_algo: "RS256")
  end

  def test_oidc_authorize_post_authorize_with_none_response_type
    setup_application
    login

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=none"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"

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
      oauth_jwt_keys("RS256" => jws_key)
      oauth_jwt_public_keys("RS256" => jws_public_key)
    end
    setup_application
    login

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=code+token&response_mode=query"
    assert current_url.include?("#error=invalid_request")

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=code+token"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"

    # submit authorization request
    click_button "Authorize"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#access_token=([^&]+)&token_type=bearer&expires_in=3600&code=([^&]+)/,
           "was redirected instead to #{page.current_url}"
    assert db[:oauth_grants].count >= 1,
           "no grant has been created"
    verify_access_token(Regexp.last_match(1), db[:oauth_grants].first, signing_key: jws_public_key, signing_algo: "RS256")
  end

  def test_oidc_authorize_post_authorize_with_code_id_token_response_type
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_keys("RS256" => jws_key)
    end
    setup_application
    login

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=code+id_token&nonce=NONCE&response_mode=query"
    assert current_url.include?("#error=invalid_request")

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=code+id_token&nonce=NONCE"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"

    # submit authorization request
    click_button "Authorize"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#id_token=([^&]+)&code=([^&]+)/,
           "was redirected instead to #{page.current_url}"

    assert db[:oauth_grants].count >= 1,
           "no grant has been created"

    verify_id_token(Regexp.last_match(1), db[:oauth_grants].first, signing_key: jws_public_key, signing_algo: "RS256")
  end

  def test_oidc_authorize_post_authorize_with_id_token_token_response_type
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_keys("RS256" => jws_key)
      oauth_jwt_public_keys("RS256" => jws_public_key)
    end
    setup_application
    login

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=id_token+token&nonce=NONCE&response_mode=query"
    assert current_url.include?("#error=invalid_request")

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=id_token+token&nonce=NONCE"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"

    # submit authorization request
    click_button "Authorize"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#access_token=([^&]+)&token_type=bearer&expires_in=3600&id_token=([^&]+)/,
           "was redirected instead to #{page.current_url}"
    verify_access_token(Regexp.last_match(1), db[:oauth_grants].first, signing_key: jws_public_key, signing_algo: "RS256")
    verify_id_token(Regexp.last_match(2), db[:oauth_grants].first, signing_key: jws_public_key, signing_algo: "RS256")
  end

  def test_oidc_authorize_post_authorize_with_code_id_token_token_response_type
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_keys("RS256" => jws_key)
      oauth_jwt_public_keys("RS256" => jws_public_key)
    end
    setup_application
    login

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=code+id_token+token&nonce=NONCE&response_mode=query"
    assert current_url.include?("#error=invalid_request")

    # show the authorization form
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=code+id_token+token&nonce=NONCE"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"

    # submit authorization request
    click_button "Authorize"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#access_token=([^&]+)&token_type=bearer&expires_in=3600&code=([^&]+)&id_token=([^&]+)/,
           "was redirected instead to #{page.current_url}"

    assert db[:oauth_grants].count >= 1,
           "no grant has been created"
    verify_access_token(Regexp.last_match(1), db[:oauth_grants].first, signing_key: jws_public_key, signing_algo: "RS256")
    verify_id_token(Regexp.last_match(3), db[:oauth_grants].first, signing_key: jws_public_key, signing_algo: "RS256")
  end

  def test_oidc_authorize_post_authorize_prompt_none_login_required
    setup_application

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&" \
          "prompt=none"
    assert page.current_url.include?("?error=login_required"),
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_authorize_post_authorize_prompt_none_interaction_required
    setup_application
    login

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&" \
          "prompt=none"
    assert page.current_url.include?("?error=interaction_required"),
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_authorize_post_authorize_prompt_none_auto_authorize
    rodauth do
      oidc_authorize_on_prompt_none? do |_account|
        true
      end
    end
    setup_application
    login

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=code&" \
          "prompt=none"

    assert db[:oauth_grants].count == 1, "new grant not created"
    new_grant = db[:oauth_grants].first
    assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{new_grant[:code]}",
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_authorize_post_authorize_offline_access
    setup_application
    login

    oauth_application = set_oauth_application(scopes: "openid")

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid offline_access&response_type=code"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    refute_includes page.html, "offline"

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid offline_access&response_type=token&" \
          "prompt=consent"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    refute_includes page.html, "offline"

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid offline_access&response_type=code&" \
          "prompt=consent"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    assert_includes page.html, "offline"

    check "openid"
    # submit authorization request
    click_button "Authorize"

    new_grant = db[:oauth_grants].order(:id).last
    assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{new_grant[:code]}",
           "was redirected instead to #{page.current_url}"
    assert new_grant[:access_type] == "offline"
  end

  def test_oidc_authorize_post_authorize_prompt_login
    setup_application

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=code&" \
          "prompt=login"
    assert page.current_path.include?("/login"),
           "was redirected instead to #{page.current_url}"

    login(visit: false)

    assert page.current_url.end_with?("/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=code&prompt=login"),
           "was redirected instead to #{page.current_url}"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"
    # submit authorization request
    click_button "Authorize"

    new_grant = db[:oauth_grants].order(:id).last
    assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{new_grant[:code]}",
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_authorize_post_authorize_prompt_select_account_with_login
    hash = BCrypt::Password.create("0123456789", cost: BCrypt::Engine::MIN_COST)
    db[:accounts].insert(email: "foo2@example.com", status_id: 2, ph: hash)

    setup_application(:select_account)

    login
    logout
    login(login: "foo2@example.com")
    logout

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=code&" \
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

    assert page.current_url.end_with?("/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=code&prompt=select-account"),
           "was redirected instead to #{page.current_url}"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"
    # submit authorization request
    click_button "Authorize"

    new_grant = db[:oauth_grants].order(:id).last
    assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{new_grant[:code]}",
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_authorize_post_authorize_prompt_login_with_reauthentication
    setup_application
    login

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=code&" \
          "prompt=login"
    assert page.current_path.start_with?("/login"),
           "was redirected instead to #{page.current_url}"

    login(visit: false)

    assert page.current_url.end_with?("/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=code&prompt=login"),
           "was redirected instead to #{page.current_url}"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"
    # submit authorization request
    click_button "Authorize"

    new_grant = db[:oauth_grants].order(:id).last
    assert page.current_url == "#{oauth_application[:redirect_uri]}?code=#{new_grant[:code]}",
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_authorize_post_authorize_prompt_consent
    setup_application
    login

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=code&" \
          "prompt=consent"
    click_button "Authorize"
    assert page.current_url.include?("?error=consent_required"),
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_authorize_post_authorize_with_id_token_signed_alg
    jws_rs256_key = OpenSSL::PKey::RSA.generate(2048)
    jws_rs512_key = OpenSSL::PKey::RSA.generate(2048)
    jws_rs512_public_key = jws_rs512_key.public_key
    rodauth do
      oauth_jwt_keys("RS256" => jws_rs256_key, "RS512" => jws_rs512_key)
    end
    setup_application
    login

    application = oauth_application(id_token_signed_response_alg: "RS512")

    # show the authorization form
    visit "/authorize?client_id=#{application[:client_id]}&scope=openid&response_type=id_token&nonce=NONCE"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"

    # submit authorization request
    click_button "Authorize"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#id_token=([^&]+)/,
           "was redirected instead to #{page.current_url}"

    verify_id_token(Regexp.last_match(1), db[:oauth_grants].first, signing_key: jws_rs512_public_key, signing_algo: "RS512")
  end

  def test_oidc_authorize_post_authorize_with_id_token_signed_encrypted_alg
    jwe_key = OpenSSL::PKey::RSA.new(2048)
    jwe_hs512_key = OpenSSL::PKey::RSA.new(2048)
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_keys("RS256" => jws_key)
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
    visit "/authorize?client_id=#{application[:client_id]}&scope=openid&response_type=id_token&nonce=NONCE"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"

    # submit authorization request
    click_button "Authorize"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#id_token=([^&]+)/,
           "was redirected instead to #{page.current_url}"

    verify_id_token(Regexp.last_match(1), db[:oauth_grants].first, signing_key: jws_public_key, decryption_key: jwe_hs512_key,
                                                                   signing_algo: "RS256")
  end

  # minimum level of support required for this parameter is simply that its use must not result in an error.
  %w[page popup touch wap].each do |display|
    define_method :"test_oidc_authorize_post_authorize_display_#{display}" do
      setup_application
      login

      visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=code&" \
            "display=consent"
      assert page.current_path == "/authorize",
             "was redirected instead to #{page.current_path}"
    end
  end

  def test_oidc_authorize_post_authorize_ui_locales
    setup_application
    login

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=code&" \
          "ui_locales=pt de es"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    assert page.html.include?("Autorizar")
  end

  def test_oidc_authorize_post_authorize_id_token_claims_locales
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_keys("RS256" => jws_key)
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
          "claims_locales=pt en&response_type=id_token&nonce=NONCE"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"

    check "name"
    # submit authorization request
    click_button "Authorize"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#id_token=([^&]+)/,
           "was redirected instead to #{page.current_url}"

    verify_id_token(
      Regexp.last_match(1),
      db[:oauth_grants].first,
      signing_key: jws_public_key,
      signing_algo: "RS256"
    ) do |claims|
      assert claims["name#pt"] == "Tiago"
      assert claims["name#en"] == "James"
    end
  end

  def test_oidc_authorize_post_authorize_code_id_token_claims_locales
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_keys("RS256" => jws_key)
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
          "claims_locales=pt en&response_type=code id_token"
    assert current_url.include?("#error=invalid_request")
    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid name&" \
          "claims_locales=pt en&response_type=code id_token&nonce=NONCE"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"

    check "name"
    # submit authorization request
    click_button "Authorize"
    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#id_token=([^&]+)&code=([^&]+)/,
           "was redirected instead to #{page.current_url}"

    grant = db[:oauth_grants].first
    assert grant[:claims_locales] == "pt en"

    verify_id_token(
      Regexp.last_match(1),
      db[:oauth_grants].first,
      signing_key: jws_public_key,
      signing_algo: "RS256"
    ) do |claims|
      assert claims["name#pt"].nil?
      assert claims["name#en"].nil?
    end
  end

  def test_oidc_authorize_post_authorize_code_id_token_claims_essentials
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_keys("RS256" => jws_key)
      get_oidc_param do |account, claim|
        case claim
        when :name
          "James"
        when :nickname
          "Snoop"
        else
          account[claim]
        end
      end
      get_additional_param do |account, claim|
        case claim
        when :foo
          "bar"
        else
          account[claim]
        end
      end
    end
    setup_application
    login

    oauth_application(scopes: "openid name")

    claims = JSON.dump({
                         "userinfo" => { "name" => { "essential " => true } },
                         "id_token" => {
                           "nickname" => { "essential " => true },
                           "foo" => {
                             "essential" => true,
                             "values" => %w[bar ba2]
                           }
                         }
                       })

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&" \
          "claims=#{CGI.escape(claims)}&response_type=code id_token&nonce=NONCE"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"
    # submit authorization request
    click_button "Authorize"
    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#id_token=([^&]+)&code=([^&]+)/,
           "was redirected instead to #{page.current_url}"

    grant = db[:oauth_grants].first
    assert grant[:claims] == claims

    verify_id_token(
      Regexp.last_match(1),
      db[:oauth_grants].first,
      signing_key: jws_public_key,
      signing_algo: "RS256"
    ) do |idtoken_claims|
      assert idtoken_claims["name"].nil?
      assert idtoken_claims["nickname"] == "Snoop"
      assert idtoken_claims["foo"] == "bar"
    end
  end

  def test_oidc_authorize_post_authorize_code_id_token_claims_scope
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_keys("RS256" => jws_key)
      get_oidc_param do |_account, claim|
        case claim
        when :email
          "james@example.org"
        when :email_verified
          true
        end
      end
    end
    setup_application
    login

    oauth_application(scopes: "openid email")

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid email&" \
          "response_type=code id_token&nonce=NONCE"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"
    check "email"
    # submit authorization request
    click_button "Authorize"
    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#id_token=([^&]+)&code=([^&]+)/,
           "was redirected instead to #{page.current_url}"

    grant = db[:oauth_grants].first
    assert grant[:claims].nil?

    verify_id_token(
      Regexp.last_match(1),
      db[:oauth_grants].first,
      signing_key: jws_public_key,
      signing_algo: "RS256"
    ) do |idtoken_claims|
      assert idtoken_claims["email"] == "james@example.org"
      assert idtoken_claims["email_verified"]
    end
  end

  unless RUBY_ENGINE == "truffleruby"
    def test_oidc_authorize_post_authorize_max_age
      setup_application
      login

      visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=code&" \
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

    visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=code&" \
          "acr_values=phr"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
  end

  def test_oidc_authorize_post_authorize_acr_value_phr_with_2factor
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_keys("RS256" => jws_key)
      oauth_jwt_public_keys("RS256" => jws_public_key)
      enable :otp
      two_factor_auth_return_to_requested_location? true
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
          "acr_values=phr&nonce=NONCE"
    assert page.current_path == "/otp-auth",
           "was redirected instead to #{page.current_path}"
    fill_in "Authentication Code", with: totp.now
    click_button "Authenticate Using TOTP"

    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    check "openid"
    # submit authorization request
    click_button "Authorize"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#id_token=([^&]+)/,
           "was redirected instead to #{page.current_url}"
    verify_id_token(Regexp.last_match(1), db[:oauth_grants].first, signing_key: jws_public_key, signing_algo: "RS256") do |claims|
      assert claims["acr"] == "phr"
    end
  end

  begin
    require "webauthn/fake_client"
  rescue LoadError
  else
    def test_oidc_authorize_post_authorize_acr_value_phrh_with_2factor_webauthn
      jws_key = OpenSSL::PKey::RSA.generate(2048)
      jws_public_key = jws_key.public_key
      rodauth do
        oauth_jwt_keys("RS256" => jws_key)
        oauth_jwt_public_keys("RS256" => jws_public_key)
        enable :webauthn_login
        two_factor_auth_return_to_requested_location? true
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

      visit "/authorize?client_id=#{oauth_application[:client_id]}&scope=openid&response_type=code id_token&" \
            "acr_values=phrh&nonce=NONCE"
      assert page.current_path == "/webauthn-auth",
             "was redirected instead to #{page.current_path}"
      challenge = JSON.parse(page.find("#webauthn-auth-form")["data-credential-options"])["challenge"]
      fill_in "webauthn_auth", with: webauthn_client.get(challenge: challenge).to_json
      click_button "Authenticate Using WebAuthn"

      assert page.current_path == "/authorize",
             "was redirected instead to #{page.current_path}"

      check "openid"
      # submit authorization request
      click_button "Authorize"

      assert page.current_url =~ /#{oauth_application[:redirect_uri]}#id_token=([^&]+)/,
             "was redirected instead to #{page.current_url}"
      verify_id_token(Regexp.last_match(1), db[:oauth_grants].first, signing_key: jws_public_key, signing_algo: "RS256") do |claims|
        assert claims["acr"] == "phrh"
      end
    end
  end

  def test_oidc_authorize_post_authorize_self_issued
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    rodauth do
      oauth_jwt_keys("RS256" => jws_key)
      oauth_jwt_public_keys("RS256" => jws_public_key)

      # this shouldn't be required, but the default test app is setting openid only
      oauth_application_scopes %w[openid profile email address phone]
    end
    setup_application(:oidc_self_issued)
    login

    redirect_uri = "https://example.com/callback"
    client_parameters = JSON.dump({
                                    name: "Self Issued Foo"
                                  })

    # show the authorization form
    visit "/authorize?client_id=#{redirect_uri}&registration=#{CGI.escape(client_parameters)}&scope=openid&response_type=id_token&nonce=NONCE"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"

    assert page.html.include?("The application Self Issued Foo would like to access your data")
    check "openid"

    # submit authorization request
    click_button "Authorize"

    assert page.current_url =~ /#{oauth_application[:redirect_uri]}#id_token=([^&]+)/,
           "was redirected instead to #{page.current_url}"
    verify_id_token(Regexp.last_match(1), db[:oauth_grants].first, signing_key: jws_public_key, signing_algo: "RS256") do |claims|
      assert !claims["sub_jwk"].nil?
      assert claims["iss"] == "https://self-issued.me"
      assert claims["sub"] == Base64.urlsafe_encode64(JWT::JWK::Thumbprint.new(JWT::JWK.new(claims["sub_jwk"])).generate, padding: false)
    end
  end

  private

  def setup_application(*)
    rodauth do
      oauth_jwt_keys("RS256" => OpenSSL::PKey::RSA.generate(2048))
      oauth_applications_jwks_column :jwks
      oauth_response_mode "query"
    end
    super
  end

  def reset_otp_last_use
    db[:account_otp_keys].update(last_use: Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, seconds: 600))
  end

  def generate_signed_request(application, signing_key: OpenSSL::PKey::RSA.generate(2048), encryption_key: nil)
    claims = {
      iss: application[:client_id],
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
