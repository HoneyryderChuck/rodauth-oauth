# frozen_string_literal: true

require "test_helper"
require "webmock/minitest"

class RodauthOauthJwtSecuredAuthorizationRequestAuthorizeTest < JWTIntegration
  include WebMock::API

  def test_jwt_authorize_with_invalid_request
    setup_application
    login

    visit "/authorize?request=eyIknowthisisbad.yes.yes&client_id=#{oauth_application[:client_id]}&response_mode=query"
    assert page.current_url.include?("?error=invalid_request_object"),
           "was redirected instead to #{page.current_url}"
  end

  def test_jwt_authorize_unverifiable_request
    setup_application
    login

    rsa_private = OpenSSL::PKey::RSA.generate(2048)
    rsa_public = rsa_private.public_key
    rodauth do
      oauth_jwt_keys("RS256" => rsa_private)
      oauth_jwt_public_keys("RS256" => rsa_public)
    end

    signed_request = generate_signed_request(oauth_application)

    visit "/authorize?request=#{signed_request}&client_id=#{oauth_application[:client_id]}&response_mode=query"
    assert page.current_url.include?("?error=invalid_request_object"),
           "was redirected instead to #{page.current_url}"
  end

  def test_jwt_authorize_with_signed_request_jwks
    setup_application
    login

    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key

    application = oauth_application(jwks: JSON.dump([JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256")]))

    signed_request = generate_signed_request(application, signing_key: jws_key)

    visit "/authorize?request=#{signed_request}&client_id=#{application[:client_id]}"
    check "user.read"
    click_button "Authorize"

    assert page.current_url.include?("code="),
           "was redirected instead to #{page.current_url}"
  end

  def test_jwt_authorize_with_signed_request_jwks_with_state
    setup_application
    login

    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key

    application = oauth_application(jwks: JSON.dump([JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256")]))

    signed_request = generate_signed_request(application, signing_key: jws_key, state: "123")

    visit "/authorize?request=#{signed_request}&client_id=#{application[:client_id]}"
    check "user.read"
    click_button "Authorize"

    assert page.current_url.include?("state=123"),
           "was redirected instead to #{page.current_url}"
  end

  def test_jwt_authorize_with_signed_request_jwks_without_aud_and_iss
    setup_application
    login

    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key

    application = oauth_application(jwks: JSON.dump([JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256")]))

    signed_request = generate_signed_request(application, signing_key: jws_key, iss: nil)
    visit "/authorize?request=#{signed_request}&client_id=#{application[:client_id]}"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_url}"

    signed_request = generate_signed_request(application, signing_key: jws_key, aud: nil)
    visit "/authorize?request=#{signed_request}&client_id=#{application[:client_id]}"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_url}"

    signed_request = generate_signed_request(application, signing_key: jws_key, iss: nil, aud: "http://www.example2.com")
    visit "/authorize?request=#{signed_request}&client_id=#{application[:client_id]}&response_mode=query"
    assert page.current_url.include?("error=invalid_request_object"),
           "was redirected instead to #{page.current_url}"

    signed_request = generate_signed_request(application, signing_key: jws_key, iss: "http://www.example2.com")
    visit "/authorize?request=#{signed_request}&client_id=#{application[:client_id]}&response_mode=query"
    assert page.current_url.include?("error=invalid_request_object"),
           "was redirected instead to #{page.current_url}"
  end

  def test_jwt_authorize_with_signed_request_jwks_request_object_signing_alg
    setup_application
    login

    jws_256_key = OpenSSL::PKey::RSA.generate(2048)
    jws_512_key = OpenSSL::PKey::RSA.generate(2048)

    application = oauth_application(
      jwks: JSON.dump([
                        JWT::JWK.new(jws_256_key.public_key).export.merge(use: "sig", alg: "RS256"),
                        JWT::JWK.new(jws_512_key.public_key).export.merge(use: "sig", alg: "RS512")
                      ]),
      request_object_signing_alg: "RS512"
    )

    visit "/authorize?request=#{generate_signed_request(application, signing_key: jws_256_key, signing_algorithm: 'RS256')}&" \
          "client_id=#{application[:client_id]}&response_mode=query"

    assert page.current_url.include?("?error=invalid_request_object"),
           "was redirected instead to #{page.current_url}"

    visit "/authorize?request=#{generate_signed_request(application, signing_key: jws_512_key, signing_algorithm: 'RS512')}&" \
          "client_id=#{application[:client_id]}&response_mode=query"

    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
  end

  def test_jwt_authorize_with_signed_request_jwks_uri
    setup_application
    login

    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key

    stub_request(:get, "https://example.com/jwks")
      .to_return(
        headers: { "Expires" => (Time.now + 3600).httpdate },
        body: JSON.dump([JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256")])
      )

    application = oauth_application(jwks_uri: "https://example.com/jwks")

    signed_request = generate_signed_request(application, signing_key: jws_key)

    visit "/authorize?request=#{signed_request}&client_id=#{application[:client_id]}"

    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
  end

  def test_jwt_authorize_with_signed_encrypted_request
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
  end

  def test_jwt_authorize_with_signed_encrypted_jwks_request
    jwe_key = OpenSSL::PKey::RSA.new(2048)
    jwe_hs512_key = OpenSSL::PKey::RSA.new(2048)
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key

    setup_application
    login

    application = oauth_application(
      jwks: JSON.dump([
                        JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256"),
                        JWT::JWK.new(jwe_key).export(include_private: true).merge(use: "enc", alg: "RSA-OAEP", enc: "A128CBC-HS256"),
                        JWT::JWK.new(jwe_hs512_key).export(include_private: true).merge(use: "enc", alg: "RSA-OAEP", enc: "A256CBC-HS512")
                      ]),
      request_object_signing_alg: "RS256",
      request_object_encryption_alg: "RSA-OAEP",
      request_object_encryption_enc: "A256CBC-HS512"
    )

    signed_request = generate_signed_request(application, signing_key: jws_key, encryption_key: jwe_key, encryption_method: "A128CBC-HS256")
    visit "/authorize?request=#{signed_request}&client_id=#{application[:client_id]}&response_mode=query"
    assert page.current_path == "/callback",
           "was redirected instead to #{page.current_path}"

    signed_request = generate_signed_request(application, signing_key: jws_key, encryption_key: jwe_hs512_key,
                                                          encryption_method: "A256CBC-HS512")
    visit "/authorize?request=#{signed_request}&client_id=#{application[:client_id]}"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"

    # a signed request should also be able to go through
    signed_request = generate_signed_request(application, signing_key: jws_key)
    visit "/authorize?request=#{signed_request}&client_id=#{application[:client_id]}"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
  end

  def test_jwt_request_uri_authorize_with_invalid_request_uri
    setup_application
    login

    visit "/authorize?request_uri=bla&client_id=#{oauth_application[:client_id]}&response_mode=query"
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

    visit "/authorize?request_uri=#{CGI.escape(request_uri)}&client_id=#{oauth_application[:client_id]}&response_mode=query"
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

    visit "/authorize?request_uri=#{CGI.escape(request_uri2)}&client_id=#{application[:client_id]}&response_mode=query"
    assert page.current_url.include?("?error=invalid_request_uri"),
           "was redirected instead to #{page.current_path}"

    visit "/authorize?request_uri=#{CGI.escape(request_uri)}&client_id=#{application[:client_id]}&response_mode=query"
    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
  end

  private

  def setup_application(*)
    rodauth do
      oauth_applications_jwks_column :jwks
    end
    super
  end

  def oauth_feature
    %i[oauth_authorization_code_grant oauth_jwt_secured_authorization_request]
  end
end
