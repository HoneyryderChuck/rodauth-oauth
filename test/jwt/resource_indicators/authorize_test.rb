# frozen_string_literal: true

require "test_helper"
require "webmock/minitest"

class RodauthOauthResourceIndicatorsJwtAuthorizeTest < JWTIntegration
  include WebMock::API

  def test_jwt_authorize_with_signed_request_with_resource
    setup_application
    login

    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key

    application = oauth_application(jwks: JSON.dump([JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256")]))

    invalid_signed_request = generate_signed_request(application, signing_key: jws_key, resource: "bla")

    visit "/authorize?request=#{invalid_signed_request}&client_id=#{application[:client_id]}"

    assert page.current_url.end_with?("?error=invalid_target"),
           "was redirected instead to #{page.current_url}"

    signed_request = generate_signed_request(application, signing_key: jws_key, resource: "https://example.org")

    visit "/authorize?request=#{signed_request}&client_id=#{application[:client_id]}"

    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
  end

  private

  def setup_application(*)
    rodauth do
      enable :oauth_resource_indicators
    end
    super
  end
end
