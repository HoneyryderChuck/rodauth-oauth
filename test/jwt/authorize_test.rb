# frozen_string_literal: true

require "test_helper"
require "webmock/minitest"

class RodauthOauthJwtAuthorizeTest < JWTIntegration
  include WebMock::API

  def test_jwt_authorize_with_request_uri
    setup_application
    login

    visit "/authorize?request_uri=https://request-uri.com/yadayada"
    assert page.current_url.include?("?error=request_uri_not_supported"),
           "was redirected instead to #{page.current_url}"
  end

  def test_jwt_authorize_with_invalid_request
    setup_application
    login

    visit "/authorize?request=eyIknowthisisbad.yes.yes&client_id=#{oauth_application[:client_id]}"
    assert page.current_url.include?("?error=invalid_request_object"),
           "was redirected instead to #{page.current_url}"
  end

  def test_jwt_authorize_unverifiable_request
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

  def test_jwt_authorize_with_signed_request_jwks
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
          "client_id=#{application[:client_id]}"

    assert page.current_url.include?("?error=invalid_request_object"),
           "was redirected instead to #{page.current_url}"

    visit "/authorize?request=#{generate_signed_request(application, signing_key: jws_512_key, signing_algorithm: 'RS512')}&" \
          "client_id=#{application[:client_id]}"

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
      oauth_jwt_audience "Example"
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

  def test_jwt_authorize_with_signed_encrypted_jwks_request
    jwe_key = OpenSSL::PKey::RSA.new(2048)
    jwe_hs512_key = OpenSSL::PKey::RSA.new(2048)
    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key

    rodauth do
      oauth_jwt_audience "Example"
    end
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
    visit "/authorize?request=#{signed_request}&client_id=#{application[:client_id]}"
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

  private

  def setup_application(*)
    rodauth do
      oauth_jwt_algorithm "RS256"
      oauth_applications_jwks_column :jwks
    end
    super
  end
end
