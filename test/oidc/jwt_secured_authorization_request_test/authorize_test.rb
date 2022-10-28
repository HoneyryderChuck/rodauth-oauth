# frozen_string_literal: true

require "test_helper"
require "webmock/minitest"

class RodauthOauthOIDCJwtSecuredAuthorizationRequestAuthorizeTest < OIDCIntegration
  include WebMock::API

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
      oauth_jwt_keys("RS256" => rsa_private)
      oauth_jwt_public_keys("RS256" => rsa_public)
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
           "was redirected instead to #{page.current_url}"

    check "openid"
    click_button "Authorize"
    assert page.current_url.include?("code="),
           "was redirected instead to #{page.current_url}"
  end

  def test_oidc_authorize_with_signed_request_state_and_nonce
    setup_application
    login

    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key

    application = oauth_application(jwks: JSON.dump([JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256")]))

    signed_request = generate_signed_request(application, signing_key: jws_key, state: "123", nonce: "456")

    visit "/authorize?request=#{signed_request}&client_id=#{application[:client_id]}"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_url}"

    check "openid"
    click_button "Authorize"

    assert page.current_url.include?("state=123"),
           "was redirected instead to #{page.current_url}"

    assert db[:oauth_grants].count == 1
    oauth_grant = db[:oauth_grants].first

    assert oauth_grant[:nonce] == "456"
  end

  def test_oidc_authorize_with_signed_encrypted_request
    jwe_key = OpenSSL::PKey::RSA.new(2048)
    jwe_public_key = jwe_key.public_key
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key

    rodauth do
      oauth_jwt_jwe_keys(%w[RSA-OAEP A128CBC-HS256] => jwe_key)
    end
    setup_application
    login

    application = oauth_application(jwks: JSON.dump([JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256")]))

    signed_request = generate_signed_request(application, signing_key: jws_key, encryption_key: jwe_public_key)

    visit "/authorize?request=#{signed_request}&client_id=#{application[:client_id]}"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"

    check "openid"
    click_button "Authorize"
    assert page.current_url.include?("code="),
           "was redirected instead to #{page.current_url}"
  end

  def test_jwt_request_uri_authorize_with_invalid_request_uri
    setup_application
    login

    visit "/authorize?request_uri=bla&client_id=#{oauth_application[:client_id]}"
    assert page.current_url.include?("?error=invalid_request_uri"),
           "was redirected instead to #{page.current_url}"
  end

  def test_jwt_request_uri_authorize_unverifiable_request
    setup_application
    login

    rsa_private = OpenSSL::PKey::RSA.generate(2048)
    rsa_public = rsa_private.public_key
    rodauth do
      oauth_jwt_keys("RS256" => rsa_private)
      oauth_jwt_public_keys("RS256" => rsa_public)
    end

    signed_request = generate_signed_request(oauth_application)

    request_uri = "https://example.com/jwts/123"

    stub_request(:get, request_uri)
      .to_return(
        headers: { "Cache-Control" => "max-age=3600", "Content-Type" => "application/oauth-authz-req+jwt" },
        body: signed_request
      )

    visit "/authorize?request_uri=#{CGI.escape(request_uri)}&client_id=#{oauth_application[:client_id]}"
    assert page.current_url.include?("?error=invalid_request_object"),
           "was redirected instead to #{page.current_url}"
  end

  def test_jwt_request_uri_authorize_with_signed_request_jwks
    setup_application
    login

    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key

    application = oauth_application(
      jwks: JSON.dump([JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256")]),
      request_uris: "https://example.com/jwts"
    )

    signed_request = generate_signed_request(application, signing_key: jws_key)

    request_uri = "https://example.com/jwts/123"
    stub_request(:get, request_uri)
      .to_return(
        headers: { "Cache-Control" => "max-age=3600", "Content-Type" => "application/oauth-authz-req+jwt" },
        body: signed_request
      )

    request_uri2 = "https://example2.com/jwts/123"
    stub_request(:get, request_uri)
      .to_return(
        headers: { "Cache-Control" => "max-age=3600", "Content-Type" => "application/oauth-authz-req+jwt" },
        body: signed_request
      )

    visit "/authorize?request_uri=#{CGI.escape(request_uri2)}&client_id=#{application[:client_id]}"
    assert page.current_url.include?("?error=invalid_request_uri"),
           "was redirected instead to #{page.current_path}"

    visit "/authorize?request_uri=#{CGI.escape(request_uri)}&client_id=#{application[:client_id]}"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"

    check "openid"
    click_button "Authorize"
    assert page.current_url.include?("code="),
           "was redirected instead to #{page.current_url}"
  end

  private

  def setup_application(*)
    rodauth do
      oauth_jwt_keys("RS256" => OpenSSL::PKey::RSA.generate(2048))
      oauth_applications_jwks_column :jwks
    end
    super
  end

  def reset_otp_last_use
    db[:account_otp_keys].update(last_use: Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, seconds: 600))
  end

  def generate_signed_request(application, signing_key: OpenSSL::PKey::RSA.generate(2048), encryption_key: nil, **extra_claims)
    claims = {
      iss: "http://www.example.com",
      aud: "http://www.example.com",
      response_mode: "query",
      response_type: "code",
      client_id: application[:client_id],
      redirect_uri: application[:redirect_uri],
      scope: application[:scopes],
      state: "ABCDEF"
    }.merge(extra_claims)

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

  def oauth_feature
    %i[oauth_jwt_secured_authorization_request oidc]
  end
end
