# frozen_string_literal: true

require "test_helper"
require "webmock/minitest"

class RodauthOidcDynamicClientRegistrationTest < OIDCIntegration
  include Rack::Test::Methods
  include WebMock::API

  def test_oidc_client_registration_response_type_id_token
    setup_application(:oauth_implicit_grant)
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

  def test_oidc_client_registration_native_application_type
    rodauth do
      oauth_valid_uri_schemes %w[http https newapp]
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

  def test_oidc_client_registration_web_application_type
    rodauth do
      oauth_valid_uri_schemes %w[http https]
    end
    setup_application(:oauth_implicit_grant)
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

  def test_oidc_client_registration_subject_type
    rodauth do
      oauth_valid_uri_schemes %w[http https]
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

    redirect_uris = %w[https://foobar.com/callback https://foobar.com/callback2]

    stub_request(:get, "https://fail.example.net/file_of_redirect_uris.json")
      .to_return(body: JSON.dump(%w[https://google.com]))

    post("/register", valid_registration_params.merge(
                        "redirect_uris" => redirect_uris,
                        "subject_type" => "pairwise",
                        "sector_identifier_uri" => "https://fail.example.net/file_of_redirect_uris.json"
                      ))
    assert last_response.status == 400

    stub_request(:get, "https://succ.example.net/file_of_redirect_uris.json")
      .to_return(body: JSON.dump(redirect_uris))

    post("/register", valid_registration_params.merge(
                        "redirect_uris" => redirect_uris,
                        "subject_type" => "pairwise",
                        "sector_identifier_uri" => "https://succ.example.net/file_of_redirect_uris.json"
                      ))
    assert last_response.status == 201
  end

  def test_oidc_client_registration_request_uris
    rodauth do
      oauth_require_request_uri_registration true
    end
    setup_application(:oauth_jwt_secured_authorization_request)
    header "Accept", "application/json"

    post("/register", valid_registration_params.merge(
                        "request_uris" => "bla"
                      ))

    assert last_response.status == 400

    post("/register", valid_registration_params.merge(
                        "request_uris" => %w[https://registero.com]
                      ))

    assert last_response.status == 201

    post("/register", valid_registration_params)

    assert last_response.status == 400
  end

  def test_oidc_client_registration_id_token_signed_response
    setup_application
    header "Accept", "application/json"

    post("/register", valid_registration_params.merge("id_token_signed_response_alg" => "smth"))

    assert last_response.status == 400

    post("/register", valid_registration_params.merge("id_token_signed_response_alg" => "RS256"))
    assert last_response.status == 201

    post("/register", valid_registration_params.merge("id_token_encrypted_response_alg" => "smth"))

    assert last_response.status == 400

    post("/register", valid_registration_params.merge("id_token_encrypted_response_alg" => "RSA-OAEP"))

    assert last_response.status == 201
    assert JSON.parse(last_response.body)["id_token_encrypted_response_alg"] == "RSA-OAEP"
    assert JSON.parse(last_response.body)["id_token_encrypted_response_enc"] == "A128CBC-HS256"

    post("/register", valid_registration_params.merge("id_token_encrypted_response_enc" => "smth"))

    assert last_response.status == 400

    post("/register", valid_registration_params.merge("id_token_encrypted_response_enc" => "A128GCM"))

    assert last_response.status == 201
  end

  def test_oidc_client_registration_userinfo_signed_response
    setup_application
    header "Accept", "application/json"

    post("/register", valid_registration_params.merge("userinfo_signed_response_alg" => "smth"))

    assert last_response.status == 400

    post("/register", valid_registration_params.merge("userinfo_signed_response_alg" => "RS256"))

    assert last_response.status == 201

    post("/register", valid_registration_params.merge("userinfo_encrypted_response_alg" => "smth"))

    assert last_response.status == 400

    post("/register", valid_registration_params.merge("userinfo_encrypted_response_alg" => "RSA-OAEP"))

    assert last_response.status == 201
    assert JSON.parse(last_response.body)["userinfo_encrypted_response_alg"] == "RSA-OAEP"
    assert JSON.parse(last_response.body)["userinfo_encrypted_response_enc"] == "A128CBC-HS256"

    post("/register", valid_registration_params.merge("userinfo_encrypted_response_enc" => "smth"))

    assert last_response.status == 400

    post("/register", valid_registration_params.merge("userinfo_encrypted_response_enc" => "A128GCM"))

    assert last_response.status == 201
  end

  def test_oidc_client_registration_request_object
    setup_application(:oauth_jwt_secured_authorization_request)
    header "Accept", "application/json"

    post("/register", valid_registration_params.merge("request_object_signing_alg" => "smth"))

    assert last_response.status == 400

    post("/register", valid_registration_params.merge("request_object_signing_alg" => "RS256"))

    assert last_response.status == 201

    post("/register", valid_registration_params.merge("request_object_encryption_alg" => "smth"))

    assert last_response.status == 400

    post("/register", valid_registration_params.merge("request_object_encryption_alg" => "RSA-OAEP"))

    assert last_response.status == 201
    assert JSON.parse(last_response.body)["request_object_encryption_alg"] == "RSA-OAEP"
    assert JSON.parse(last_response.body)["request_object_encryption_enc"] == "A128CBC-HS256"

    post("/register", valid_registration_params.merge("request_object_encryption_enc" => "smth"))

    assert last_response.status == 400

    post("/register", valid_registration_params.merge("request_object_encryption_enc" => "A128GCM"))

    assert last_response.status == 201
  end

  private

  def setup_application(*)
    rodauth do
      before_register {} # no auth
    end
    super
  end

  def oauth_feature
    :oidc_dynamic_client_registration
  end

  def valid_registration_params
    @valid_registration_params ||= {
      "redirect_uris" => %w[https://foobar.com/callback https://foobar.com/callback2],
      "token_endpoint_auth_method" => "client_secret_post",
      "grant_types" => %w[authorization_code refresh_token], # default: authorization code
      "response_types" => %w[code], # default code,
      "client_name" => "This client name",
      "client_uri" => "https://foobar.com",
      "logo_uri" => "https://foobar.com/logo.png",
      "scope" => "openid",
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
