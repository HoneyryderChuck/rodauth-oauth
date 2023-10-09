# frozen_string_literal: true

require "test_helper"

class RodauthOauthOidcServerMetadataTest < OIDCIntegration
  include Rack::Test::Methods
  include TestSchemas::Methods

  def test_oidc_openid_configuration
    rsa_private = OpenSSL::PKey::RSA.generate(2048)
    rodauth do
      oauth_application_scopes %w[openid email]
      oauth_jwt_keys("RS256" => rsa_private)
    end
    setup_application
    get("/.well-known/openid-configuration")

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"
    assert json_body["issuer"] == "http://example.org"
    assert json_body["authorization_endpoint"] == "http://example.org/authorize"
    assert !json_body["end_session_endpoint"]
    assert json_body["token_endpoint"] == "http://example.org/token"
    assert json_body["userinfo_endpoint"] == "http://example.org/userinfo"
    assert json_body["jwks_uri"] == "http://example.org/jwks"
    assert json_body["scopes_supported"] == %w[openid email]
    assert json_body["response_types_supported"] == [
      "code", "token", "id_token", "none",
      "code id_token",
      "code token",
      "id_token token",
      "code id_token token"
    ]
    assert json_body["response_modes_supported"] == %w[query form_post fragment]
    assert json_body["grant_types_supported"] == %w[refresh_token authorization_code implicit]
    assert json_body["subject_types_supported"] == %w[public pairwise]

    assert json_body["token_endpoint_auth_methods_supported"] == %w[client_secret_basic client_secret_post]
    assert json_body["token_endpoint_auth_signing_alg_values_supported"] == %w[RS256]

    # assert json_body["display_values_supported"] == %w[RS256]
    assert json_body["claim_types_supported"] == %w[normal]
    assert json_body["claims_supported"] == %w[sub iss iat exp aud auth_time email email_verified]
  end

  def test_oidc_metadata_openid_configuration_cors
    rodauth do
      oauth_application_scopes %w[openid email.email]
    end
    setup_application

    options("/.well-known/openid-configuration")

    assert last_response.status == 200
    assert last_response.headers["Access-Control-Allow-Origin"] == "*"
    assert last_response.headers["Access-Control-Allow-Methods"] == "GET, OPTIONS"
    assert last_response.headers["Access-Control-Max-Age"] == "3600"
  end

  def test_filters_out_invalid_fields
    rsa_private = OpenSSL::PKey::RSA.generate(2048)
    rodauth do
      oauth_jwt_keys("RS256" => rsa_private)
      oauth_application_scopes %w[openid email]
    end
    setup_application
    get("/.well-known/openid-configuration")

    assert_schema :oidc_configuration_response, json_body
    assert !json_body.key?("code_challenge_methods_supported")
    assert !json_body.key?("revocation_endpoint_auth_methods_supported")
  end

  def test_oidc_metadata_openid_configuration_sub_scopes
    rodauth do
      oauth_application_scopes %w[openid email.email]
    end
    setup_application

    get("/.well-known/openid-configuration")

    assert last_response.status == 200

    assert json_body["claims_supported"] == %w[sub iss iat exp aud auth_time email]
  end

  def test_oidc_metadata_openid_configuration_rp_initiated_logout
    setup_application(:oidc_rp_initiated_logout)

    get("/.well-known/openid-configuration")

    assert last_response.status == 200

    assert json_body["end_session_endpoint"] == "http://example.org/oidc-logout"
  end

  def test_oidc_metadata_openid_configuration_frontchannel_logout
    setup_application(:oidc_frontchannel_logout)

    get("/.well-known/openid-configuration")

    assert last_response.status == 200

    assert json_body["frontchannel_logout_supported"] == true
    assert json_body["frontchannel_logout_session_supported"] == true
  end

  def test_oidc_metadata_openid_configuration_backchannel_logout
    setup_application(:oidc_backchannel_logout)

    get("/.well-known/openid-configuration")

    assert last_response.status == 200

    assert json_body["backchannel_logout_supported"] == true
    assert json_body["backchannel_logout_session_supported"] == true
  end

  private

  def setup_application(*args)
    rodauth do
      last_account_login_at do
        Time.now - 60
      end
    end
    super(*args, &:load_openid_configuration_route)
  end
end
