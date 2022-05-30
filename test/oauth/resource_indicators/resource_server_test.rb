# frozen_string_literal: true

require "test_helper"
require "webmock/minitest"

class RodauthOAuthResourceIndicatorsResourceServerTest < RodaIntegration
  include Rack::Test::Methods
  include WebMock::API

  def test_token_access_private_no_token
    setup_application

    header "Accept", "application/json"
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_invalid_resource
    setup_application

    header "Accept", "application/json"
    header "Authorization", "Bearer TOKEN"
    stub_request(:post, "https://auth-server/introspect")
      .with(body: "token_type_hint=access_token&token=TOKEN")
      .to_return(body: JSON.dump({
                                   "scope" => "profile.read",
                                   "active" => true,
                                   "client_id" => "CLIENT_ID",
                                   "aud" => %w[http://smthelse.com]
                                 }))
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_valid_resource
    setup_application

    header "Accept", "application/json"
    header "Authorization", "Bearer TOKEN"
    stub_request(:post, "https://auth-server/introspect")
      .with(body: "token_type_hint=access_token&token=TOKEN")
      .to_return(body: JSON.dump({
                                   "scope" => "profile.read",
                                   "active" => true,
                                   "client_id" => "CLIENT_ID",
                                   "aud" => %w[http://example.org]
                                 }))
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  private

  def setup_application
    resource_server = Class.new(Roda)
    resource_server.plugin :rodauth do
      enable :oauth, :oauth_resource_indicators
      is_authorization_server? false
      authorization_server_url "https://auth-server"
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
