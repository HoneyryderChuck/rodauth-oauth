# frozen_string_literal: true

require "test_helper"

# Applications registered before "token_endpoint_auth_method" was a thing, or created outside of the
# dynamic client registration endpoint, have no auth method of their own. What the server accepts
# from them must not change every time a new auth method is enabled server-wide.
class RodauthOauthTokenEndpointAuthMethodTest < RodaIntegration
  include Rack::Test::Methods

  def test_application_without_auth_method_rejects_none
    rodauth do
      oauth_token_endpoint_auth_methods_supported %w[client_secret_basic client_secret_post none]
    end
    setup_application
    header "Accept", "application/json"

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: "CODE")

    assert last_response.status == 401
    assert json_body["error"] == "invalid_client"
  end

  def test_application_without_auth_method_accepts_client_secret
    rodauth do
      oauth_token_endpoint_auth_methods_supported %w[client_secret_basic client_secret_post none]
    end
    setup_application
    header "Accept", "application/json"

    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: "CODE")

    assert last_response.status == 400
    assert json_body["error"] == "invalid_grant"
  end

  def test_application_with_none_auth_method
    rodauth do
      oauth_token_endpoint_auth_methods_supported %w[client_secret_basic client_secret_post none]
    end
    setup_application
    header "Accept", "application/json"

    application = set_oauth_application(client_id: "PUBLIC_ID", token_endpoint_auth_method: "none")

    post("/token",
         client_id: application[:client_id],
         grant_type: "authorization_code",
         code: "CODE")

    assert last_response.status == 400
    assert json_body["error"] == "invalid_grant"
  end

  def test_application_without_auth_method_with_default_override
    rodauth do
      oauth_token_endpoint_auth_methods_supported %w[client_secret_basic client_secret_post none]
      oauth_default_token_endpoint_auth_methods %w[client_secret_basic client_secret_post none]
    end
    setup_application
    header "Accept", "application/json"

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: "CODE")

    assert last_response.status == 400
    assert json_body["error"] == "invalid_grant"
  end
end
