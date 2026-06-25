# frozen_string_literal: true

require "test_helper"
require_relative "token_authorization_code"

class RodauthOAuthTokenAuthorizationCodeClientSecretBasicTest < RodaIntegration
  include RodauthOAuthTokenAuthorizationCodeTest

  def test_token_authorization_code_client_secret_post
    setup_application
    oauth_app = oauth_application(token_endpoint_auth_method: "client_secret_basic")
    oauth_grant = set_oauth_grant(oauth_application: oauth_app)

    post("/token",
         client_id: oauth_app[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    verify_response(401)

    header "Authorization", "Basic #{authorization_header(
      username: oauth_app[:client_id],
      password: 'CLIENT_SECRET'
    )}"
    post("/token", grant_type: "authorization_code",
                   code: oauth_grant[:code],
                   redirect_uri: oauth_grant[:redirect_uri])
    verify_response(200)
  end

  def test_token_authorization_code_invalid_client_id
    setup_application
    oauth_app = oauth_application(token_endpoint_auth_method: "client_secret_basic")
    oauth_grant = set_oauth_grant(oauth_application: oauth_app)

    header "Authorization", "Basic #{authorization_header(
      username: 'INVALID_CLIENT_ID',
      password: oauth_app[:client_secret]
    )}"

    post("/token",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    verify_response(401)
    assert json_body["error"] == "invalid_client"
  end

  # With client-secret hashing disabled, secret_matches? compares the stored
  # plaintext secret against the supplied one; that comparison must be
  # constant-time. We override timing_safe_eql? on the auth class to record its
  # arguments and assert the plaintext branch routed through it. A regression to
  # a plain == comparison records no such call and this fails.
  def test_token_authorization_code_plaintext_client_secret_uses_timing_safe_compare
    calls = []
    rodauth do
      oauth_applications_client_secret_hash_column nil
      auth.send(:define_method, :timing_safe_eql?) do |provided, actual|
        calls << [provided, actual]
        super(provided, actual)
      end
    end
    setup_application

    oauth_app = oauth_application(token_endpoint_auth_method: "client_secret_basic", client_secret: "CLIENT_SECRET")
    oauth_grant = set_oauth_grant(oauth_application: oauth_app)

    header "Authorization", "Basic #{authorization_header(
      username: oauth_app[:client_id],
      password: 'CLIENT_SECRET'
    )}"
    post("/token", grant_type: "authorization_code",
                   code: oauth_grant[:code],
                   redirect_uri: oauth_grant[:redirect_uri])

    verify_response(200)
    assert_includes calls, %w[CLIENT_SECRET CLIENT_SECRET],
                    "plaintext client-secret check did not route through timing_safe_eql?"
  end

  # A missing submitted secret must not authenticate a plaintext client whose stored secret is
  # empty. Basic credentials carrying only the client id (no colon) decode to a nil client_secret;
  # coercing it to "" would match an empty stored secret and bypass authentication.
  def test_token_authorization_code_plaintext_empty_secret_rejects_missing_secret
    rodauth do
      oauth_applications_client_secret_hash_column nil
    end
    setup_application

    oauth_app = oauth_application(token_endpoint_auth_method: "client_secret_basic", client_secret: "")
    oauth_grant = set_oauth_grant(oauth_application: oauth_app)

    header "Authorization", "Basic #{Base64.urlsafe_encode64(oauth_app[:client_id])}"
    post("/token", grant_type: "authorization_code",
                   code: oauth_grant[:code],
                   redirect_uri: oauth_grant[:redirect_uri])

    verify_response(401)
    assert json_body["error"] == "invalid_client"
  end

  private

  def post_token(request_args)
    header "Authorization", "Basic #{authorization_header(
      username: request_args.delete(:client_id) || oauth_application[:client_id],
      password: 'CLIENT_SECRET'
    )}"

    post("/token", request_args)
  end
end
