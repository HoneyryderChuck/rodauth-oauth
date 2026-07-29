# frozen_string_literal: true

require "test_helper"

# https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
#
# Token endpoint errors must be delivered in the response body, no matter what the client
# sends in the "Accept" header. Clients calling the token endpoint have no way of reading a
# response which is bounced off their own redirect uri.
class RodauthOauthTokenErrorResponseTest < RodaIntegration
  include Rack::Test::Methods

  def test_token_error_without_accept_header
    setup_application

    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         code: "CODE")

    assert last_response.status == 400
    assert last_response.headers["Content-Type"] == "application/json"
    assert last_response.headers["Location"].nil?
    assert json_body["error"] == "invalid_request"
  end

  def test_token_error_without_accept_header_html_response_mode
    rodauth do
      oauth_response_mode "form_post"
    end
    setup_application

    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         code: "CODE")

    assert last_response.status == 400
    assert last_response.headers["Content-Type"] == "application/json"
    assert !last_response.body.include?("<form")
    assert json_body["error"] == "invalid_request"
  end

  def test_token_error_with_accept_header
    setup_application
    header "Accept", "application/json"

    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         code: "CODE")

    assert last_response.status == 400
    assert last_response.headers["Content-Type"] == "application/json"
    assert json_body["error"] == "invalid_request"
  end

  def test_token_invalid_client_without_accept_header
    setup_application

    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "WRONG_SECRET",
         grant_type: "authorization_code",
         code: "CODE")

    assert last_response.status == 401
    assert last_response.headers["Content-Type"] == "application/json"
    assert last_response.headers["Location"].nil?
    assert json_body["error"] == "invalid_client"
  end

  def test_token_no_credentials_without_accept_header
    setup_application

    post("/token", grant_type: "authorization_code", code: "CODE")

    assert last_response.status == 401
    assert last_response.headers["Content-Type"] == "application/json"
    assert last_response.headers["Location"].nil?
    assert json_body["error"] == "invalid_client"
  end
end
