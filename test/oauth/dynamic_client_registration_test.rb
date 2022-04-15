# frozen_string_literal: true

require "test_helper"

class RodauthOauthDynamicClientRegistrationTest < RodaIntegration
  include Rack::Test::Methods

  def test_oauth_no_dynamic_client_registration
    rodauth do
      oauth_application_scopes %w[read write]
    end
    setup_application
    header "Accept", "application/json"

    post("/register", {
           redirect_uris: %w[https://foobar.com/callback],
           token_endpoint_auth_method: "client_secret_post",
           grant_types: %w[authorization_code refresh_token], # default: authorization code
           response_types: %w[code], # default code,
           client_name: "This client name",
           client_uri: "https://foobar.com",
           logo_uri: "https://foobar.com/logo.png",
           scope: %w[read write],
           contacts: %w[emp@mail.com],
           tos_uri: "https://foobar.com/tos",
           policy_uri: "https://foobar.com/policy",
           jwks_uri: "https://foobar.com/jwks",
           software_id: "12",
           software_version: "XHR-123"
         })

    assert last_response.status == 401
  end

  def test_oauth_dynamic_client_wrong_params
    rodauth do
      enable :oauth_dynamic_client_registration
      oauth_application_scopes %w[read write]
    end
    setup_application
    header "Accept", "application/json"

    post("/register", { first_name: "Bada", last_name: "Bing" })

    assert last_response.status == 400
    assert json_body["error"] == "invalid_client_metadata"
  end

  def test_oauth_dynamic_client_redirect_uris
    rodauth do
      enable :oidc_dynamic_client_registration
      oauth_application_scopes %w[read write]
    end
    setup_application
    header "Accept", "application/json"

    post("/register", valid_registration_params.merge("redirect_uris" => "https://just-one.com"))

    assert last_response.status == 400

    post("/register", valid_registration_params.merge("redirect_uris" => %w[one two]))

    assert last_response.status == 400

    post("/register", valid_registration_params.merge("redirect_uris" => %w[https://example.com/callback]))

    assert last_response.status == 201
  end

  def test_oauth_dynamic_client_grant_types
    rodauth do
      enable :oidc_dynamic_client_registration
      oauth_application_scopes %w[read write]
    end

    setup_application
    header "Accept", "application/json"

    post("/register", valid_registration_params.merge("grant_types" => %w[smthsmth]))

    assert last_response.status == 400

    post("/register", valid_registration_params.merge("grant_types" => %w[authorization_code implicit refresh_token]))

    assert last_response.status == 400

    post("/register", valid_registration_params.merge("grant_types" => %w[authorization_code refresh_token]))

    assert last_response.status == 201
    assert JSON.parse(last_response.body)["grant_types"] == %w[authorization_code refresh_token]

    post("/register", valid_registration_params)

    assert last_response.status == 201
    assert JSON.parse(last_response.body)["grant_types"] == %w[authorization_code]
  end

  def test_oauth_dynamic_client_response_types
    rodauth do
      enable :oidc_dynamic_client_registration
      oauth_application_scopes %w[read write]
    end

    setup_application
    header "Accept", "application/json"

    post("/register", valid_registration_params.merge("response_types" => %w[smthsmth]))

    assert last_response.status == 400

    post("/register", valid_registration_params.merge("response_types" => %w[code token]))

    assert last_response.status == 400

    post("/register", valid_registration_params.merge("response_types" => %w[code]))

    assert last_response.status == 201
    assert JSON.parse(last_response.body)["response_types"] == %w[code]

    post("/register", valid_registration_params)
    assert last_response.status == 201
    assert JSON.parse(last_response.body)["response_types"] == %w[code]
  end

  def test_oauth_dynamic_client_scopes
    rodauth do
      enable :oidc_dynamic_client_registration
      oauth_application_scopes %w[read write]
    end

    setup_application
    header "Accept", "application/json"

    post("/register", valid_registration_params.merge("scope" => "this"))

    assert last_response.status == 400

    post("/register", valid_registration_params.merge("scope" => "read this"))

    assert last_response.status == 400

    post("/register", valid_registration_params.merge("scope" => "read"))
    assert last_response.status == 201
    assert JSON.parse(last_response.body)["scope"] == "read"

    post("/register", valid_registration_params)
    assert last_response.status == 201
    assert JSON.parse(last_response.body)["scope"] == "read write"
  end

  %w[client_uri logo_uri tos_uri policy_uri jwks_uri].each do |uri_param|
    define_method :"test_oauth_dynamic_client_#{uri_param}" do
      rodauth do
        enable :oidc_dynamic_client_registration
        oauth_application_scopes %w[read write]
      end

      setup_application
      header "Accept", "application/json"

      post("/register", valid_registration_params.merge(uri_param => "smthsmth"))

      assert last_response.status == 400

      post("/register", valid_registration_params.merge(uri_param => "https://example.com"))

      assert last_response.status == 201
    end
  end

  def test_oauth_dynamic_client_fail_on_missing_required_params
    rodauth do
      enable :oauth_dynamic_client_registration
      oauth_application_scopes %w[read write]
    end
    setup_application

    %w[redirect_uris client_name client_uri].each do |required_param|
      post("/register", valid_registration_params.tap { |hs| hs.delete(required_param) })
      assert last_response.status == 400
      assert JSON.parse(last_response.body)["error"] == "invalid_client_metadata"
    end
  end

  def test_oauth_dynamic_client_jwks_and_jwks_uri
    rodauth do
      enable :oauth_dynamic_client_registration
      oauth_application_scopes %w[read write]
    end
    setup_application

    post("/register", valid_registration_params.merge("jwks" => { "a" => "b" }))
    assert last_response.status == 400
    assert json_body["error"] == "invalid_client_metadata"
  end

  def test_oauth_dynamic_client_all_params_without_client_secret
    rodauth do
      enable :oauth_dynamic_client_registration
      oauth_application_scopes %w[read write]
    end
    setup_application

    post("/register", valid_registration_params)

    assert last_response.status == 201

    assert db[:oauth_applications].count == 1

    oauth_application = db[:oauth_applications].first

    assert json_body["client_id"] == oauth_application[:client_id]
    assert json_body["client_secret_expires_at"].zero?

    assert json_body.key?("client_secret")
    assert json_body.key?("client_id_issued_at")
  end

  def test_oauth_dynamic_client_all_params_with_client_secret
    rodauth do
      enable :oauth_dynamic_client_registration
      oauth_application_scopes %w[read write]
    end
    setup_application

    post("/register", valid_registration_params.merge("client_secret" => "CLIENT_SECRET"))

    assert last_response.status == 201

    assert db[:oauth_applications].count == 1

    oauth_application = db[:oauth_applications].first

    assert json_body["client_id"] == oauth_application[:client_id]

    assert json_body.key?("client_id_issued_at")
    assert !json_body.key?("client_secret")
    assert !json_body.key?("client_secret_expires_at")
  end

  def test_oauth_dynamic_client_token_endpoint_auth_method
    rodauth do
      enable :oauth_dynamic_client_registration
      oauth_application_scopes %w[read write]
    end
    setup_application

    post("/register", valid_registration_params.merge("token_endpoint_auth_method" => "client_secret_post"))
    assert last_response.status == 201
    assert JSON.parse(last_response.body)["token_endpoint_auth_method"] == "client_secret_post"

    post("/register", valid_registration_params)
    assert last_response.status == 201
    assert JSON.parse(last_response.body)["token_endpoint_auth_method"] == "client_secret_basic"
  end

  private

  def valid_registration_params
    @valid_registration_params ||= {
      "redirect_uris" => %w[https://foobar.com/callback https://foobar.com/callback2],
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
end
