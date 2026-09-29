# frozen_string_literal: true

require "test_helper"

class RodauthJwtAuthorizeTest < JWTIntegration
  include Rack::Test::Methods

  def test_authorize_post_authorize_not_logged_in_no_client_application
    setup_application
    post "/authorize"

    assert last_response.status == 401
  end

  def test_authorize_post_authorize_no_client_application
    setup_application
    login
    post "/authorize"

    assert last_response.status == 400
    assert_equal "Invalid or missing 'client_id'", json_body["error_description"]
  end

  def test_authorize_post_authorize_invalid_client_id
    setup_application
    login
    post "/authorize", { client_id: "bla" }.to_json

    assert last_response.status == 400
    assert_equal "Invalid or missing 'client_id'", json_body["error_description"]
  end

  def test_authorize_post_authorize_invalid_redirect_uri
    setup_application
    login
    post "/authorize",
         { client_id: oauth_application[:client_id],
           response_type: "code",
           redirect_uri: "bla" }.to_json

    assert last_response.status == 400
    assert_equal "Invalid or missing 'redirect_uri'", json_body["error_description"]
  end

  def test_authorize_post_authorize_invalid_scope
    setup_application
    login
    post "/authorize",
         { client_id: oauth_application[:client_id],
           response_type: "code",
           redirect_uri: oauth_application[:redirect_uri],
           scope: "marvel" }.to_json

    assert last_response.status == 400
    assert_equal "invalid_scope", json_body["error"]
  end

  def test_authorize_post_authorize_multiple_uris_no_redirect_uri
    setup_application
    login

    oauth_application(redirect_uri: "http://redirect1 http://redirect2")

    post "/authorize",
         { client_id: oauth_application[:client_id],
           scope: "user.read+user.write" }.to_json

    assert last_response.status == 400
    assert_equal "Invalid or missing 'redirect_uri'", json_body["error_description"]
  end

  def test_authorize_post_authorize_multiple_uris
    setup_application
    login

    oauth_application(redirect_uri: "http://redirect1 http://redirect2")

    post "/authorize",
         { client_id: oauth_application[:client_id],
           redirect_uri: "http://redirect2&",
           response_type: "code",
           scope: "user.read+user.write" }.to_json

    assert last_response.status == 400
    assert_equal "Invalid or missing 'redirect_uri'", json_body["error_description"]
  end

  def test_authorize_post_authorize
    setup_application
    login

    post "/authorize",
         { client_id: oauth_application[:client_id],
           response_type: "code",
           scope: "user.read" }.to_json

    assert last_response.status == 200
  end

  private

  def setup_application(*args, **kwargs)
    rodauth do
      oauth_response_mode "query"
      enable :json
    end
    super(*args, json: true, **kwargs)
    header "Accept", "application/json"
    header "Content-Type", "application/json"
  end

  def login
    header "Authorization", "Basic #{authorization_header(
      username: 'foo@example.com',
      password: '0123456789'
    )}"
  end

  def oauth_feature
    :oauth_authorization_code_grant
  end
end
