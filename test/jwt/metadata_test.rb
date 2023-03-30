# frozen_string_literal: true

require "test_helper"

class RodauthOauthJwtServerMetadataTest < JWTIntegration
  include Rack::Test::Methods

  def test_oauth_jwt_server_metadata
    jws_rs256_key = OpenSSL::PKey::RSA.generate(2048)
    jws_rs512_key = OpenSSL::PKey::RSA.generate(2048)
    rodauth do
      oauth_jwt_keys("RS256" => jws_rs256_key, "RS512" => jws_rs512_key)
    end
    setup_application(&:load_oauth_server_metadata_route)
    get("/.well-known/oauth-authorization-server")

    assert last_response.status == 200
    assert json_body["token_endpoint_auth_signing_alg_values_supported"] == %w[RS256 RS512]
    assert json_body["jwks_uri"] == "http://example.org/jwks"
  end

  def test_oauth_jwt_bearer_metadata
    setup_application(:oauth_jwt_bearer_grant, &:load_oauth_server_metadata_route)

    get("/.well-known/oauth-authorization-server")

    assert last_response.status == 200
    assert json_body["grant_types_supported"].include?("urn:ietf:params:oauth:grant-type:jwt-bearer")
    %w[client_secret_basic client_secret_post private_key_jwt].each do |auth_method|
      assert json_body["token_endpoint_auth_methods_supported"].include?(auth_method)
    end
  end

  def test_oauth_jwt_bearer_metadata_no_hashed_secret
    rodauth do
      oauth_applications_client_secret_hash_column nil
    end
    setup_application(:oauth_jwt_bearer_grant, &:load_oauth_server_metadata_route)

    get("/.well-known/oauth-authorization-server")

    assert last_response.status == 200
    assert json_body["grant_types_supported"].include?("urn:ietf:params:oauth:grant-type:jwt-bearer")
    %w[client_secret_basic client_secret_post client_secret_jwt private_key_jwt].each do |auth_method|
      assert json_body["token_endpoint_auth_methods_supported"].include?(auth_method)
    end
  end

  def test_oauth_jwt_secured_authorization_request_not_require_uri
    setup_application(:oauth_jwt_secured_authorization_request, &:load_oauth_server_metadata_route)

    get("/.well-known/oauth-authorization-server")

    assert last_response.status == 200
    assert json_body["request_parameter_supported"] == true
    assert json_body["request_uri_parameter_supported"] == true
    assert json_body["require_request_uri_registration"] == false
  end

  def test_oauth_jwt_secured_authorization_request_require_uri
    rodauth do
      oauth_require_request_uri_registration true
    end
    setup_application(:oauth_jwt_secured_authorization_request, &:load_oauth_server_metadata_route)

    get("/.well-known/oauth-authorization-server")

    assert last_response.status == 200
    assert json_body["request_parameter_supported"] == true
    assert json_body["request_uri_parameter_supported"] == true
    assert json_body["require_request_uri_registration"] == true
  end

  def test_oauth_jwt_secured_authorization_response_mode
    rodauth do
      authorization_signing_alg_values_supported %w[RS256]
    end

    setup_application(:oauth_jwt_secured_authorization_response_mode, :oauth_authorization_code_grant, :oauth_implicit_grant,
                      &:load_oauth_server_metadata_route)

    get("/.well-known/oauth-authorization-server")

    assert last_response.status == 200

    %w[query.jwt fragment.jwt form_post.jwt jwt].each do |mode|
      assert json_body["response_modes_supported"].include?(mode)
    end

    assert json_body["authorization_signing_alg_values_supported"] == %w[RS256]
    assert json_body.key?("authorization_encryption_alg_values_supported")
    assert json_body.key?("authorization_encryption_enc_values_supported")
  end

  def test_oauth_jwt_secured_authorization_response_mode_no_implicit
    setup_application(:oauth_jwt_secured_authorization_response_mode, :oauth_authorization_code_grant,
                      &:load_oauth_server_metadata_route)

    get("/.well-known/oauth-authorization-server")

    assert last_response.status == 200

    %w[query.jwt form_post.jwt jwt].each do |mode|
      assert json_body["response_modes_supported"].include?(mode)
    end
    assert !json_body["response_modes_supported"].include?("fragment.jwt")
  end
end
