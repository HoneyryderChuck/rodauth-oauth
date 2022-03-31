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

    verify_oauth_application_attributes(oauth_application, valid_registration_params)

    assert json_body > valid_registration_params.merge(
      "client_id" => oauth_application[:client_id],
      "client_secret_expires_at" => 0
    )

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

    verify_oauth_application_attributes(oauth_application, valid_registration_params)

    assert json_body > valid_registration_params.merge("client_id" => oauth_application[:client_id])

    assert json_body.key?("client_id_issued_at")
    assert !json_body.key?("client_secret")
    assert !json_body.key?("client_secret_expires_at")
  end

  def test_oauth_dynamic_client_default_token_endpoint_auth_method
    rodauth do
      enable :oauth_dynamic_client_registration
      oauth_application_scopes %w[read write]
    end
    setup_application

    post("/register", valid_registration_params.tap { |hs| hs.delete("token_endpoint_auth_method") })
    assert last_response.status == 201
    assert db[:oauth_applications].count == 1
    oauth_application = db[:oauth_applications].first
    verify_oauth_application_attributes(oauth_application, valid_registration_params.merge(
                                                             "token_endpoint_auth_method" => "client_secret_basic"
                                                           ))
  end

  def test_oauth_dynamic_client_default_grant_types
    rodauth do
      enable :oauth_dynamic_client_registration
      oauth_application_scopes %w[read write]
    end
    setup_application

    post("/register", valid_registration_params.tap { |hs| hs.delete("grant_types") })
    assert last_response.status == 201
    assert db[:oauth_applications].count == 1
    oauth_application = db[:oauth_applications].first
    verify_oauth_application_attributes(oauth_application, valid_registration_params.merge(
                                                             "grant_types" => %w[authorization_code]
                                                           ))
  end

  def test_oauth_dynamic_client_default_response_types
    rodauth do
      enable :oauth_dynamic_client_registration
      oauth_application_scopes %w[read write]
    end
    setup_application

    post("/register", valid_registration_params.tap { |hs| hs.delete("response_types") })
    assert last_response.status == 201
    assert db[:oauth_applications].count == 1
    oauth_application = db[:oauth_applications].first
    verify_oauth_application_attributes(oauth_application, valid_registration_params.merge(
                                                             "response_types" => %w[code]
                                                           ))
  end

  def test_oauth_dynamic_client_default_scopes
    rodauth do
      enable :oauth_dynamic_client_registration
      oauth_application_scopes %w[read write]
    end
    setup_application

    post("/register", valid_registration_params.tap { |hs| hs.delete("scopes") })
    assert last_response.status == 201
    assert db[:oauth_applications].count == 1
    oauth_application = db[:oauth_applications].first
    verify_oauth_application_attributes(oauth_application, valid_registration_params.merge(
                                                             "scopes" => "read write"
                                                           ))
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
