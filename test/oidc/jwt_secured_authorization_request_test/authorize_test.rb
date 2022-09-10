# frozen_string_literal: true

require "test_helper"

class RodauthOauthOIDCJwtSecuredAuthorizationRequestAuthorizeTest < OIDCIntegration
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
           "was redirected instead to #{page.current_path}"
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

  def oauth_feature
    %i[oauth_jwt_secured_authorization_request oidc]
  end
end
