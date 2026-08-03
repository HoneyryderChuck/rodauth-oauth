# frozen_string_literal: true

require "test_helper"

class RodauthOauthClientRegistrationTest < RodaIntegration
  include Rack::Test::Methods

  def test_get_oauth_application
    setup_application

    get "/register/#{oauth_application[:client_id]}"
    assert last_response.status == 200
    assert json_body["client_id"] = oauth_application[:client_id]
    assert json_body["client_name"] = oauth_application[:name]
    verify_oauth_application_attributes(oauth_application, json_body)
  end

  def test_put_oauth_application
    setup_application

    put "/register/#{oauth_application[:client_id]}", {
      "client_id" => "NEWID"
    }
    assert last_response.status == 400

    put "/register/#{oauth_application[:client_id]}", {
      "name" => "New Name"
    }
    assert last_response.status == 200
    assert json_body["client_id"] = oauth_application[:client_id]
    assert json_body["name"] = "New Name"
    verify_oauth_application_attributes(oauth_application, json_body)
  end

  def test_put_oauth_application_client_secret
    setup_application

    put "/register/#{oauth_application[:client_id]}", {
      "client_secret" => "WRONG_SECRET"
    }
    assert last_response.status == 401
  end

  def test_put_oauth_application_only_updates_authenticated_client
    setup_application

    # authenticated client (Bearer CLIENT_TOKEN, set in setup_application)
    attacker = oauth_application
    victim = set_oauth_application(
      name: "Victim",
      client_id: "VICTIM_ID",
      client_secret: generate_client_secret("VICTIM_SECRET"),
      registration_access_token: generate_client_secret("VICTIM_TOKEN"),
      redirect_uri: "https://victim.example/callback"
    )

    put "/register/#{attacker[:client_id]}", {
      "client_name" => "pwned",
      "redirect_uris" => %w[https://attacker.example/callback]
    }
    assert last_response.status == 200

    victim_row = db[:oauth_applications].where(client_id: victim[:client_id]).first
    assert_equal "Victim", victim_row[:name]
    assert_equal "https://victim.example/callback", victim_row[:redirect_uri]
  end

  def test_delete_oauth_application
    setup_application

    delete "/register/#{oauth_application[:client_id]}", {
      "client_id" => "NEWID"
    }
    assert last_response.status == 204
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
    super(*args, &:load_registration_client_uri_routes)
    header "Accept", "application/json"
    header "Authorization", "Bearer CLIENT_TOKEN"
  end
end
