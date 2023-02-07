# frozen_string_literal: true

require "test_helper"

class RodauthOauthClientRegistrationTest < RodaIntegration
  include Rack::Test::Methods

  def test_get_oauth_application
    setup_application

    get "/oauth-applications/#{oauth_application[:client_id]}"
    assert last_response.status == 200
    assert json_body["client_id"] = oauth_application[:client_id]
    assert json_body["client_name"] = oauth_application[:name]
    verify_oauth_application_attributes(oauth_application, json_body)
  end

  def test_patch_oauth_application
    setup_application

    patch "/oauth-applications/#{oauth_application[:client_id]}", {
      "client_id" => "NEWID"
    }
    assert last_response.status == 400

    patch "/oauth-applications/#{oauth_application[:client_id]}", {
      "name" => "New Name"
    }
    assert last_response.status == 200
    assert json_body["client_id"] = oauth_application[:client_id]
    assert json_body["name"] = "New Name"
    verify_oauth_application_attributes(oauth_application, json_body)
  end

  private

  def verify_oauth_application_attributes(oauth_application, params)
    assert oauth_application[:redirect_uri] == params["redirect_uris"].join(" ")
    assert oauth_application[:token_endpoint_auth_method] == params["token_endpoint_auth_method"]
    assert oauth_application[:homepage_url] == params["client_uri"]
    assert oauth_application[:logo_uri] == params["logo_uri"]
    assert oauth_application[:scopes] == params["scope"]
    assert oauth_application[:tos_uri] == params["tos_uri"]
    assert oauth_application[:policy_uri] == params["policy_uri"]
    assert oauth_application[:jwks_uri] == params["jwks_uri"]
    assert oauth_application[:software_id] == params["software_id"]
    assert oauth_application[:software_version] == params["software_version"]
  end

  def oauth_feature
    :oauth_dynamic_client_registration
  end

  def setup_application(*args)
    super(*args, &:load_client_registration_uri_routes)
    header "Accept", "application/json"
    header "Authorization", "Bearer CLIENT_TOKEN"
  end
end
