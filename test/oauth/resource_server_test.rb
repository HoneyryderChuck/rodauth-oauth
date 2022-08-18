# frozen_string_literal: true

require "test_helper"
require "webmock/minitest"

class RodauthOAuthResourceServerTest < RodaIntegration
  include Rack::Test::Methods
  include WebMock::API

  def test_token_access_private_no_token
    setup_application

    header "Accept", "application/json"
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_inactive_token
    setup_application

    header "Accept", "application/json"
    header "Authorization", "Bearer TOKEN"
    stub_request(:post, "https://auth-server/introspect")
      .with(body: "token_type_hint=access_token&token=TOKEN")
      .to_return(body: JSON.dump({ "active" => false }))
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_invalid_scope
    setup_application

    header "Accept", "application/json"
    header "Authorization", "Bearer TOKEN"
    stub_request(:post, "https://auth-server/introspect")
      .with(body: "token_type_hint=access_token&token=TOKEN")
      .to_return(body: JSON.dump({
                                   "scope" => "profile.write",
                                   "active" => true,
                                   "client_id" => "CLIENT_ID"
                                 }))
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_valid_token
    setup_application

    header "Accept", "application/json"
    header "Authorization", "Bearer TOKEN"
    stub_request(:post, "https://auth-server/introspect")
      .with(body: "token_type_hint=access_token&token=TOKEN")
      .to_return(body: JSON.dump({
                                   "scope" => "profile.read",
                                   "active" => true,
                                   "client_id" => "CLIENT_ID"
                                 }))
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  def test_token_access_private_auth_server_with_path
    setup_application("https://auth-server/oauth")

    header "Accept", "application/json"
    header "Authorization", "Bearer TOKEN"
    stub_request(:post, "https://auth-server/oauth/introspect")
      .with(body: "token_type_hint=access_token&token=TOKEN")
      .to_return(body: JSON.dump({
                                   "scope" => "profile.read",
                                   "active" => true,
                                   "client_id" => "CLIENT_ID"
                                 }))
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  private

  def setup_application(auth_url = "https://auth-server")
    resource_server = Class.new(Roda)
    resource_server.plugin :rodauth do
      enable :oauth
      is_authorization_server? false
      authorization_server_url auth_url
    end
    resource_server.route do |r|
      rodauth.require_oauth_authorization("profile.read")
      r.get "private" do
        r.get do
          "Authorized"
        end
      end
    end
    self.app = resource_server
  end
end
