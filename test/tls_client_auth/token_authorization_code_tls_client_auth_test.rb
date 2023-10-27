# frozen_string_literal: true

require "test_helper"
require_relative "tls_helpers"
require_relative "../oauth/authorization_code_grant/token_authorization_code"

class RodauthOAuthTokenAuthorizationCodeTlsClientAuthTest < RodaIntegration
  include RodauthOAuthTlsHelpers
  include RodauthOAuthTokenAuthorizationCodeTest

  def test_token_authorization_code_no_params
    setup_application

    post("/token")
    verify_response(401)
    assert json_body["error"] == "invalid_client"
  end

  def test_token_authorization_code_no_client_secret
    setup_application

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    verify_response(401)
    assert json_body["error"] == "invalid_client"
  end

  def test_token_authorization_code_self_signed
    setup_application

    oauth_application = set_oauth_application(
      token_endpoint_auth_method: "self_signed_tls_client_auth"
    )
    oauth_grant = set_oauth_grant(oauth_application: oauth_application)

    post_token(client_id: oauth_application[:client_id],
               grant_type: "authorization_code",
               code: oauth_grant[:code],
               redirect_uri: oauth_grant[:redirect_uri])

    verify_response(200)

    assert db[:oauth_grants].count == 1
    oauth_grant = db[:oauth_grants].first
    verify_access_token_response(json_body, oauth_grant)
  end

  def test_token_authorization_code_san_dns
    setup_application

    oauth_application = set_oauth_application(
      tls_client_auth_subject_dn: nil,
      tls_client_auth_san_dns: san_dns
    )
    oauth_grant = set_oauth_grant(oauth_application: oauth_application)

    post_token(client_id: oauth_application[:client_id],
               grant_type: "authorization_code",
               code: oauth_grant[:code],
               redirect_uri: oauth_grant[:redirect_uri])

    verify_response(200)

    assert db[:oauth_grants].count == 1
    oauth_grant = db[:oauth_grants].first
    verify_access_token_response(json_body, oauth_grant)
  end

  def test_token_authorization_code_san_uri
    setup_application

    oauth_application = set_oauth_application(
      tls_client_auth_subject_dn: nil,
      tls_client_auth_san_uri: san_uri
    )
    oauth_grant = set_oauth_grant(oauth_application: oauth_application)

    post_token(client_id: oauth_application[:client_id],
               grant_type: "authorization_code",
               code: oauth_grant[:code],
               redirect_uri: oauth_grant[:redirect_uri])

    verify_response(200)

    assert db[:oauth_grants].count == 1
    oauth_grant = db[:oauth_grants].first
    verify_access_token_response(json_body, oauth_grant)
  end

  def test_token_authorization_code_san_ip
    setup_application

    oauth_application = set_oauth_application(
      tls_client_auth_subject_dn: nil,
      tls_client_auth_san_ip: san_ip
    )
    oauth_grant = set_oauth_grant(oauth_application: oauth_application)

    post_token(client_id: oauth_application[:client_id],
               grant_type: "authorization_code",
               code: oauth_grant[:code],
               redirect_uri: oauth_grant[:redirect_uri])

    verify_response(200)

    assert db[:oauth_grants].count == 1
    oauth_grant = db[:oauth_grants].first
    verify_access_token_response(json_body, oauth_grant)
  end

  def test_token_authorization_code_san_email
    setup_application

    oauth_application = set_oauth_application(
      tls_client_auth_subject_dn: nil,
      tls_client_auth_san_email: san_email
    )
    oauth_grant = set_oauth_grant(oauth_application: oauth_application)

    post_token(client_id: oauth_application[:client_id],
               grant_type: "authorization_code",
               code: oauth_grant[:code],
               redirect_uri: oauth_grant[:redirect_uri])

    verify_response(200)

    assert db[:oauth_grants].count == 1
    oauth_grant = db[:oauth_grants].first
    verify_access_token_response(json_body, oauth_grant)
  end

  def test_token_authorization_code_successful
    setup_application

    post_token(client_id: oauth_application[:client_id],
               grant_type: "authorization_code",
               code: oauth_grant[:code],
               redirect_uri: oauth_grant[:redirect_uri])

    verify_response(200)

    assert db[:oauth_grants].count == 1

    oauth_grant = db[:oauth_grants].first

    verify_access_token_response(json_body, oauth_grant)
  end

  private

  def post_token(request_args)
    set_ssl_meta_vars

    request_args = {
      client_id: request_args.delete(:client_id) || oauth_application[:client_id]
    }.merge(request_args).compact

    post("/token", request_args)
  end

  def oauth_feature
    %i[oauth_jwt_base oauth_authorization_code_grant oauth_tls_client_auth]
  end
end
