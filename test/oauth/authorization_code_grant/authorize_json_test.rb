# frozen_string_literal: true

require "test_helper"

class RodauthOauthAuthorizeJsonTest < RodaIntegration
  include Rack::Test::Methods

  def test_authorize_post_authorize_not_logged_in_no_client_application
    setup_application

    post("/authorize", {
           client_id: "bla"
         })
    assert last_response.status == 401
    assert json_body["error"] == "Please login to continue"
  end

  def test_authorize_get_authorize_invalid_client_id
    setup_application
    login
    post("/authorize", {
           client_id: "bla"
         })
    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
  end

  def test_authorize_post_authorize_invalid_redirect_uri
    setup_application
    login
    post("/authorize", {
           client_id: oauth_application[:client_id],
           redirect_uri: "bla"
         })
    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
  end

  def test_authorize_get_authorize_invalid_scope
    setup_application
    login
    post("/authorize", {
           client_id: oauth_application[:client_id],
           redirect_uri: oauth_application[:redirect_uri],
           scope: "marvel"
         })
    assert last_response.status == 400
    assert json_body["error"] == "invalid_scope"
  end

  def test_authorize_post_authorize
    setup_application
    login
    post("/authorize", {
           client_id: oauth_application[:client_id],
           redirect_uri: oauth_application[:redirect_uri],
           scope: "user.read user.write"
         })
    assert last_response.status == 200
    assert json_body.key?("callback_url")
    assert json_body["callback_url"].match(/#{oauth_application[:redirect_uri]}\?code=(.+)/)

    assert db[:oauth_grants].count == 1,
           "no grant has been created"
  end

  private

  def setup_application
    rodauth do
      use_json? true
      use_jwt? true
      jwt_secret "SECRET"
    end
    super(:jwt, :json)
    header "Accept", "application/json"
  end

  def login(opts = {})
    post("/login", {
           login: opts.fetch(:login, "foo@example.com"),
           password: opts.fetch(:pass, "0123456789")
         })
    assert last_response.status == 200, "login failed"
    header "Authorization", last_response.headers["authorization"]
  end
end
