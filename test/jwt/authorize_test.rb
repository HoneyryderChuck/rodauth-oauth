# frozen_string_literal: true

require "test_helper"

class RodauthOauthJwtAuthorizeTest < JWTIntegration
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
    rodauth do
      oauth_jwt_audience "Example"
    end
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

  def test_jwt_authorize_with_signed_request
    rodauth do
      oauth_jwt_audience "Example"
    end
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

    application = oauth_application(jws_jwk: JSON.dump(JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256")))

    signed_request = generate_signed_request(application, signing_key: jws_key, encryption_key: jwe_public_key)

    visit "/authorize?request=#{signed_request}&client_id=#{application[:client_id]}"

    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
  end

  private

  def setup_application
    rodauth do
      oauth_application_jws_jwk_column :jws_jwk
    end
    super
  end

  def generate_signed_request(application, signing_key: OpenSSL::PKey::RSA.generate(2048), encryption_key: nil)
    claims = {
      iss: "Example",
      aud: "Example",
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
