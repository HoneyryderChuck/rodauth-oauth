# frozen_string_literal: true

require "test_helper"
require_relative "tls_helpers"

class RodauthOauthJWTTokenTlsClientAuuthCertificateBoundTest < JWTIntegration
  include Rack::Test::Methods
  include RodauthOAuthTlsHelpers

  def test_oauth_jwt_authorization_code_not_certificate_bound
    setup_application

    post_token(
      client_id: oauth_application[:client_id],
      grant_type: "authorization_code",
      code: oauth_grant[:code],
      redirect_uri: oauth_grant[:redirect_uri]
    )

    verify_response

    oauth_grant = verify_oauth_grant

    verify_access_token_response(json_body, oauth_grant, @rsa_public, "RS256")
    assert !json_body.key?("cnf")
  end

  def test_oauth_jwt_authorization_code_config_certificate_bound
    rodauth do
      oauth_tls_client_certificate_bound_access_tokens true
    end
    setup_application

    post_token(client_id: oauth_application[:client_id],
               grant_type: "authorization_code",
               code: oauth_grant[:code],
               redirect_uri: oauth_grant[:redirect_uri])

    verify_response

    oauth_grant = verify_oauth_grant

    claims = verify_access_token_response(json_body, oauth_grant, @rsa_public, "RS256")
    assert claims.key?("cnf")
    assert claims["cnf"].key?("x5t#S256")
    assert claims["cnf"]["x5t#S256"] == oauth_grant[:certificate_thumbprint]
  end

  def test_oauth_jwt_authorization_code_application_certificate_bound
    rodauth do
      oauth_tls_client_certificate_bound_access_tokens false
    end
    setup_application
    oauth_application = set_oauth_application(
      tls_client_certificate_bound_access_tokens: true
    )
    oauth_grant = set_oauth_grant(
      oauth_application: oauth_application
    )

    post_token(client_id: oauth_application[:client_id],
               grant_type: "authorization_code",
               code: oauth_grant[:code],
               redirect_uri: oauth_grant[:redirect_uri])

    verify_response

    oauth_grant = verify_oauth_grant

    claims = verify_access_token_response(json_body, oauth_grant, @rsa_public, "RS256")
    assert claims.key?("cnf")
    assert claims["cnf"].key?("x5t#S256")
    assert claims["cnf"]["x5t#S256"] == oauth_grant[:certificate_thumbprint]
  end

  private

  def setup_application(*)
    rsa_private = OpenSSL::PKey::RSA.generate 2048
    @rsa_public = rsa_private.public_key
    rodauth do
      oauth_jwt_keys("RS256" => rsa_private)
      oauth_jwt_public_keys("RS256" => @rsa_public)
    end
    super
  end

  def post_token(request_args)
    set_ssl_meta_vars

    request_args = {
      client_id: request_args.delete(:client_id) || oauth_application[:client_id]
    }.merge(request_args).compact

    post("/token", request_args)
  end

  def oauth_feature
    %i[oauth_authorization_code_grant oauth_jwt oauth_tls_client_auth]
  end
end
