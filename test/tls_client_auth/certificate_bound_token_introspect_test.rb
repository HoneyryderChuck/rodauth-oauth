# frozen_string_literal: true

require "test_helper"
require_relative "tls_helpers"

class RodauthOAuthCertificateBoundTokenIntrospectTest < RodaIntegration
  include Rack::Test::Methods
  include RodauthOAuthTlsHelpers

  def test_oauth_introspect_missing_token
    setup_application

    header "Accept", "application/json"

    post_introspect
    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
  end

  def test_oauth_introspect_expired_token
    setup_application
    login

    header "Accept", "application/json"

    grant = oauth_grant_with_token(
      expires_in: Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, seconds: 20),
      certificate_thumbprint: generate_thumbprint(public_key)
    )

    # valid token, and now we're getting somewhere
    post_introspect({
                      token: grant[:token]
                    })
    assert last_response.status == 200
    assert json_body == { "active" => false }
  end

  def test_oauth_introspect_unknown_token_hint
    setup_application

    header "Accept", "application/json"

    grant = oauth_grant_with_token(
      certificate_thumbprint: generate_thumbprint(public_key)
    )

    # valid token, and now we're getting somewhere
    post_introspect({
                      token: grant[:refresh_token],
                      token_type_hint: "wups"

                    })
    assert last_response.status == 400
    assert json_body["error"] == "unsupported_token_type"
  end

  def test_oauth_introspect_access_token
    setup_application

    header "Accept", "application/json"

    grant = oauth_grant_with_token(
      certificate_thumbprint: generate_thumbprint(public_key)
    )
    # valid token, and now we're getting somewhere
    post_introspect({
                      token: grant[:token]
                    })
    assert last_response.status == 200
    assert json_body["active"] == true
    assert json_body["username"] == account[:email]
    assert json_body["scope"] == oauth_grant_with_token[:scopes]
    assert json_body["client_id"] == oauth_application[:client_id]
    assert json_body["token_type"] == "bearer"
    assert json_body.key?("exp")
  end

  def test_oauth_introspect_refresh_token
    setup_application

    header "Accept", "application/json"
    grant = oauth_grant_with_token(
      certificate_thumbprint: generate_thumbprint(public_key)
    )

    # valid token, and now we're getting somewhere
    post_introspect({
                      token: grant[:refresh_token]
                    })
    assert last_response.status == 200
    assert json_body["active"] == true
    assert json_body["username"] == account[:email]
    assert json_body["scope"] == oauth_grant_with_token[:scopes]
    assert json_body["client_id"] == oauth_application[:client_id]
    assert json_body["token_type"] == "bearer"
    assert json_body.key?("exp")
  end

  def test_oauth_introspect_refresh_token_wrong_token_hint
    setup_application

    header "Accept", "application/json"

    grant = oauth_grant_with_token(
      certificate_thumbprint: generate_thumbprint(public_key)
    )
    # valid token, and now we're getting somewhere
    post_introspect({
                      token: grant[:refresh_token],
                      token_type_hint: "access_token"
                    })
    assert last_response.status == 200
    assert json_body == { "active" => false }
  end

  def test_oauth_introspect_refresh_token_token_hint
    setup_application

    header "Accept", "application/json"

    grant = oauth_grant_with_token(
      certificate_thumbprint: generate_thumbprint(public_key)
    )
    # valid token, and now we're getting somewhere
    post_introspect({
                      token: grant[:refresh_token],
                      token_type_hint: "refresh_token"
                    })
    assert last_response.status == 200
    assert json_body["active"] == true
  end

  def test_oauth_introspect_access_token_credentials_grant
    setup_application

    header "Accept", "application/json"

    grant = oauth_grant_with_token(
      type: "client_credentials", account_id: nil,
      certificate_thumbprint: generate_thumbprint(public_key)
    )

    # valid token, and now we're getting somewhere
    post_introspect({
                      client_id: oauth_application[:client_id],
                      client_secret: "CLIENT_SECRET",
                      token: grant[:token]
                    })
    assert last_response.status == 200
    assert json_body["active"] == true
    assert json_body["username"] == "Foo"
    assert json_body["scope"] == grant[:scopes]
    assert json_body["client_id"] == oauth_application[:client_id]
    assert json_body["token_type"] == "bearer"
    assert json_body.key?("exp")
  end

  def test_oauth_introspect_access_token_client_credentials_auth
    setup_application
    header "Accept", "application/json"
    client_credentials_grant = set_oauth_grant_with_token(type: "client_credentials", account_id: nil, token: "CLIENT_TOKEN",
                                                          refresh_token: "CLIENT_REFRESH_TOKEN")
    header "Authorization", "Bearer #{client_credentials_grant[:token]}"
    grant = oauth_grant_with_token(
      certificate_thumbprint: generate_thumbprint(public_key)
    )
    # valid token, and now we're getting somewhere
    post_introspect({
                      token: grant[:token]
                    })
    assert last_response.status == 200
    assert json_body["active"] == true
    assert json_body["username"] == account[:email]
    assert json_body["scope"] == oauth_grant_with_token[:scopes]
    assert json_body["client_id"] == oauth_application[:client_id]
    assert json_body["token_type"] == "bearer"
    assert json_body.key?("exp")
  end

  private

  def post_introspect(request_args = {})
    set_ssl_meta_vars

    request_args = {
      client_id: request_args.delete(:client_id) || oauth_application[:client_id]
    }.merge(request_args).compact

    post("/introspect", request_args)
  end

  def oauth_feature
    %i[oauth_token_introspection oauth_tls_client_auth]
  end
end
