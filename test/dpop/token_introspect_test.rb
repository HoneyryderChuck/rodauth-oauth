# frozen_string_literal: true

require "test_helper"

class RodauthOAuthDpopTokenIntrospectTest < DPoPIntegration
  include Rack::Test::Methods

  def test_token_introspection_with_dpop_bound_token
    ecdsa_key = OpenSSL::PKey::EC.generate("prime256v1")
    ecdsa_key.generate_key
    rodauth do
      oauth_jwt_keys("ES256" => ecdsa_key)
    end
    setup_application

    header "DPoP", generate_dpop_proof(ecdsa_key)
    post(
      "/token",
      client_id: oauth_application[:client_id],
      client_secret: "CLIENT_SECRET",
      grant_type: "authorization_code",
      code: oauth_grant[:code],
      redirect_uri: oauth_grant[:redirect_uri]
    )
    assert last_response.status == 200
    access_token = json_body["access_token"]

    header "Authorization", "Basic #{authorization_header(
      username: oauth_application[:client_id],
      password: 'CLIENT_SECRET'
    )}"

    # valid token, and now we're getting somewhere
    post(
      "/introspect",
      { token: access_token, token_type_hint: "access_token" }
    )

    @json_body = nil
    verify_response

    assert json_body["active"] == true
    assert json_body.key?("cnf")
    assert json_body["cnf"]["jkt"] == generate_thumbprint(ecdsa_key)
  end

  private

  def oauth_feature
    %i[oauth_authorization_code_grant oauth_token_introspection oauth_dpop]
  end
end
