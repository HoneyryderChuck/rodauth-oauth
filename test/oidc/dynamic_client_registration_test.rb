# frozen_string_literal: true

require "test_helper"

class RodauthOidcDynamicClientRegistrationTest < OIDCIntegration
  include Rack::Test::Methods

  def test_oidc_response_type_id_token
    rodauth do
      enable :oidc_dynamic_client_registration
      oauth_application_scopes %w[read write]
      use_oauth_implicit_grant_type? true
    end
    setup_application
    header "Accept", "application/json"

    post("/register", valid_registration_params.merge(
                        "grant_types" => %w[authorization_code],
                        "response_types" => %w[id_token]
                      ))

    assert last_response.status == 400

    post("/register", valid_registration_params.merge(
                        "grant_types" => %w[implicit],
                        "response_types" => %w[id_token]
                      ))

    assert last_response.status == 201
  end

  def test_oidc_native_application_type
    rodauth do
      enable :oidc_dynamic_client_registration
      oauth_valid_uri_schemes %w[http https newapp]
      oauth_application_scopes %w[read write]
    end
    setup_application
    header "Accept", "application/json"

    post("/register", valid_registration_params.merge(
                        "application_type" => "native",
                        "redirect_uris" => %w[https://example.com]
                      ))

    assert last_response.status == 400

    post("/register", valid_registration_params.merge(
                        "application_type" => "native",
                        "redirect_uris" => %w[http://example.com]
                      ))

    assert last_response.status == 400

    post("/register", valid_registration_params.merge(
                        "application_type" => "native",
                        "redirect_uris" => %w[http://localhost]
                      ))

    assert last_response.status == 201

    post("/register", valid_registration_params.merge(
                        "application_type" => "native",
                        "redirect_uris" => %w[newapp://localhost]
                      ))

    assert last_response.status == 201
  end

  def test_oidc_web_application_type
    rodauth do
      enable :oidc_dynamic_client_registration
      oauth_valid_uri_schemes %w[http https]
      oauth_application_scopes %w[read write]
      use_oauth_implicit_grant_type? true
    end
    setup_application
    header "Accept", "application/json"

    post("/register", valid_registration_params.merge(
                        "application_type" => "web",
                        "grant_types" => %w[implicit],
                        "response_types" => %w[token],
                        "redirect_uris" => %w[http://example.com]
                      ))

    assert last_response.status == 400

    post("/register", valid_registration_params.merge(
                        "application_type" => "web",
                        "grant_types" => %w[implicit],
                        "response_types" => %w[token],
                        "redirect_uris" => %w[https://example.com]
                      ))

    assert last_response.status == 201

    post("/register", valid_registration_params.merge(
                        "application_type" => "web",
                        "grant_types" => %w[authorization_code],
                        "redirect_uris" => %w[http://example.com]
                      ))

    assert last_response.status == 201
  end

  def test_oidc_subject_type
    rodauth do
      enable :oidc_dynamic_client_registration
      oauth_valid_uri_schemes %w[http https]
      oauth_application_scopes %w[read write]
    end
    setup_application
    header "Accept", "application/json"

    post("/register", valid_registration_params.merge(
                        "subject_type" => "bla"
                      ))

    assert last_response.status == 400

    post("/register", valid_registration_params.merge(
                        "subject_type" => "pairwise"
                      ))

    assert last_response.status == 201

    post("/register", valid_registration_params.merge(
                        "subject_type" => "public"
                      ))

    assert last_response.status == 201
  end

  private

  def valid_registration_params
    @valid_registration_params ||= {
      "redirect_uris" => %w[https://foobar.com/callback https://foobar.com/callback2],
      "token_endpoint_auth_method" => "client_secret_post",
      "grant_types" => %w[authorization_code refresh_token], # default: authorization code
      "response_types" => %w[code], # default code,
      "client_name" => "This client name",
      "client_uri" => "https://foobar.com",
      "logo_uri" => "https://foobar.com/logo.png",
      "scope" => "read write",
      "contacts" => %w[emp@mail.com],
      "tos_uri" => "https://foobar.com/tos",
      "policy_uri" => "https://foobar.com/policy",
      "jwks_uri" => "https://foobar.com/jwks",
      "software_id" => "12",
      "software_version" => "XHR-123"
    }
  end

  def verify_oauth_application_attributes(oauth_application, params)
    assert oauth_application[:redirect_uri] == params["redirect_uris"].join(" ")
    assert oauth_application[:token_endpoint_auth_method] == params["token_endpoint_auth_method"]
    assert oauth_application[:grant_types] == params["grant_types"].join(" ")
    assert oauth_application[:response_types] == params["response_types"].join(" ")
    assert oauth_application[:name] == params["client_name"]
    assert oauth_application[:homepage_url] == params["client_uri"]
    assert oauth_application[:logo_uri] == params["logo_uri"]
    assert oauth_application[:scopes] == params["scope"]
    assert oauth_application[:contacts] == params["contacts"].join(" ")
    assert oauth_application[:tos_uri] == params["tos_uri"]
    assert oauth_application[:policy_uri] == params["policy_uri"]
    assert oauth_application[:jwks_uri] == params["jwks_uri"]
    assert oauth_application[:software_id] == params["software_id"]
    assert oauth_application[:software_version] == params["software_version"]
  end
end
