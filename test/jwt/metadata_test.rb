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
end
