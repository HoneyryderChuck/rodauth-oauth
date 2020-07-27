# frozen_string_literal: true

require "test_helper"

class RodauthOauthOidcServerMetadataTest < OIDCIntegration
  include Rack::Test::Methods

  def test_oidc_server_metadata
    rodauth do
      oauth_application_scopes %w[openid email]
      oauth_jwt_algorithm "HS256"

      last_account_login_at do
        Time.now - 60
      end
    end
    setup_application
    get("/.well-known/openid-configuration")

    assert last_response.status == 200
    assert json_body["issuer"] == "http://example.org"
    assert json_body["authorization_endpoint"] == "http://example.org/authorize"
    assert json_body["token_endpoint"] == "http://example.org/token"
    assert json_body["userinfo_endpoint"] == "http://example.org/userinfo"
    assert json_body["jwks_uri"] == "http://example.org/jwks"
    assert json_body["registration_endpoint"] == "http://example.org/oauth-applications"
    assert json_body["scopes_supported"] == %w[openid email]
    assert json_body["response_types_supported"] == [
      "code", "none", "id_token", %w[code token],
      %w[code id_token],
      %w[id_token token],
      %w[code id_token token]
    ]
    assert json_body["response_modes_supported"] == %w[query fragment]
    assert json_body["grant_types_supported"] == %w[authorization_code implicit]
    assert json_body["subject_types_supported"] == %w[public]

    assert json_body["id_token_signing_alg_values_supported"] == %w[HS256]
    assert json_body["id_token_encryption_alg_values_supported"] == %w[]
    assert json_body["id_token_encryption_enc_values_supported"] == %w[]
    assert json_body["userinfo_signing_alg_values_supported"] == %w[]
    assert json_body["userinfo_encryption_alg_values_supported"] == %w[]
    assert json_body["userinfo_encryption_enc_values_supported"] == %w[]

    assert json_body["request_object_signing_alg_values_supported"] == %w[]
    assert json_body["request_object_encryption_alg_values_supported"] == %w[]
    assert json_body["request_object_encryption_enc_values_supported"] == %w[]

    assert json_body["token_endpoint_auth_methods_supported"] == %w[client_secret_basic client_secret_post]
    assert json_body["token_endpoint_auth_signing_alg_values_supported"] == %w[HS256]

    # assert json_body["display_values_supported"] == %w[HS256]
    assert json_body["claim_types_supported"] == %w[normal]
    assert json_body["claims_supported"] == %w[sub iss iat exp aud auth_time email email_verified]

    assert json_body["code_challenge_methods_supported"] == "S256"
  end

  private

  def setup_application
    super(&:openid_configuration)
  end
end
