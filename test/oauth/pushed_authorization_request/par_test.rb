# frozen_string_literal: true

require "test_helper"
require "webmock/minitest"

class RodauthOauthPushedAuthorizationRequestParTest < RodaIntegration
  include Rack::Test::Methods

  def test_par_with_invalid_request
    setup_application

    post("/par",
         client_id: oauth_application[:client_id],
         response_type: "code",
         redirect_uri: oauth_application[:redirect_uri])
    assert last_response.status == 401
    assert last_response.headers["Content-Type"] == "application/json"
  end

  def test_par_with_with_request_uri
    setup_application
    login

    post("/par",
         request_uri: "http://example.com")
    assert last_response.status == 400
    assert last_response.headers["Content-Type"] == "application/json"

    assert json_body["error"] == "invalid_request"
  end

  def test_par_successful_basic_auth
    setup_application
    login

    post("/par",
         response_type: "code",
         scope: "user.read",
         redirect_uri: oauth_application[:redirect_uri])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_pushed_requests].count == 1,
           "no push request has been created"
    request = db[:oauth_pushed_requests].first
    assert request[:oauth_application_id] == oauth_application[:id]

    assert json_body["request_uri"] == "urn:ietf:params:oauth:request_uri:#{request[:code]}"
    assert json_body["expires_in"] == 90
  end

  private

  def setup_application(*)
    super
    header "Accept", "application/json"
  end

  # overriding to implement the client/secret basic authorization
  def login
    header "Authorization", "Basic #{authorization_header(
      username: oauth_application[:client_id],
      password: 'CLIENT_SECRET'
    )}"
  end

  def oauth_feature
    %i[oauth_authorization_code_grant oauth_pushed_authorization_request]
  end
end
