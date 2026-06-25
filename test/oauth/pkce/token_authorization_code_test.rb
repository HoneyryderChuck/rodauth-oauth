# frozen_string_literal: true

require "test_helper"

class RodauthOAuthTokenPkceTest < RodaIntegration
  include Rack::Test::Methods

  def test_token_authorization_code_pkce_no_code_verifier
    setup_application

    pkce_grant = oauth_grant(access_type: "online", code_challenge_method: "S256", code_challenge: PKCE_CHALLENGE)

    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: pkce_grant[:code],
         redirect_uri: pkce_grant[:redirect_uri])

    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
  end

  def test_token_authorization_code_pkce_wrong_code_verifier
    setup_application

    pkce_grant = oauth_grant(access_type: "online", code_challenge_method: "S256", code_challenge: PKCE_CHALLENGE)

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: pkce_grant[:code],
         redirect_uri: pkce_grant[:redirect_uri],
         code_verifier: "FAULTY_VERIFIER")

    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
  end

  def test_token_authorization_code_pkce_unsupported_algorithm
    setup_application

    pkce_grant = oauth_grant(access_type: "online", code_challenge_method: "S384", code_challenge: PKCE_CHALLENGE)

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: pkce_grant[:code],
         redirect_uri: pkce_grant[:redirect_uri],
         code_verifier: PKCE_VERIFIER)

    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
  end

  def test_token_authorization_code_pkce_with_code_sha256_verifier
    rodauth do
      use_oauth_access_type? true
    end
    setup_application

    pkce_grant = oauth_grant(access_type: "online", code_challenge_method: "S256", code_challenge: PKCE_CHALLENGE)

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: pkce_grant[:code],
         redirect_uri: pkce_grant[:redirect_uri],
         code_verifier: PKCE_VERIFIER)

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_grants].one?

    oauth_grant = db[:oauth_grants].first

    assert json_body["access_token"] == oauth_grant[:token]
    assert json_body["refresh_token"].nil?
    assert !json_body["expires_in"].nil?
  end

  def test_token_authorization_code_pkce_with_plain_code_verifier
    rodauth do
      use_oauth_access_type? true
      oauth_pkce_allow_plain_method true
    end
    setup_application

    pkce_grant = oauth_grant(access_type: "online", code_challenge_method: "plain", code_challenge: PKCE_VERIFIER)

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: pkce_grant[:code],
         redirect_uri: pkce_grant[:redirect_uri],
         code_verifier: PKCE_VERIFIER)

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_grants].one?

    oauth_grant = db[:oauth_grants].first

    assert json_body["access_token"] == oauth_grant[:token]
    assert json_body["refresh_token"].nil?
    assert !json_body["expires_in"].nil?
  end

  def test_token_authorization_code_pkce_plain_rejected_by_default
    rodauth do
      use_oauth_access_type? true
    end
    setup_application

    pkce_grant = oauth_grant(access_type: "online", code_challenge_method: "plain", code_challenge: PKCE_VERIFIER)

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: pkce_grant[:code],
         redirect_uri: pkce_grant[:redirect_uri],
         code_verifier: PKCE_VERIFIER)

    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
    assert json_body["error_description"] == "transform algorithm not supported"

    # the grant must not be redeemed
    assert db[:oauth_grants].first[:token].nil?
  end

  # The PKCE verifier comparisons must be constant-time. We override
  # timing_safe_eql? on the auth class to record its arguments, then assert the
  # S256/plain verifier check routed through it with the expected operands. A
  # regression to a plain == comparison records no such call and these fail.
  def test_token_authorization_code_pkce_s256_uses_timing_safe_compare
    calls = []
    rodauth do
      use_oauth_access_type? true
      auth.send(:define_method, :timing_safe_eql?) do |provided, actual|
        calls << [provided, actual]
        super(provided, actual)
      end
    end
    setup_application

    pkce_grant = oauth_grant(access_type: "online", code_challenge_method: "S256", code_challenge: PKCE_CHALLENGE)

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: pkce_grant[:code],
         redirect_uri: pkce_grant[:redirect_uri],
         code_verifier: PKCE_VERIFIER)

    assert last_response.status == 200
    assert_includes calls, [PKCE_CHALLENGE, PKCE_CHALLENGE],
                    "S256 PKCE verifier check did not route through timing_safe_eql?"
  end

  def test_token_authorization_code_pkce_plain_uses_timing_safe_compare
    calls = []
    rodauth do
      use_oauth_access_type? true
      oauth_pkce_allow_plain_method true
      auth.send(:define_method, :timing_safe_eql?) do |provided, actual|
        calls << [provided, actual]
        super(provided, actual)
      end
    end
    setup_application

    pkce_grant = oauth_grant(access_type: "online", code_challenge_method: "plain", code_challenge: PKCE_VERIFIER)

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: pkce_grant[:code],
         redirect_uri: pkce_grant[:redirect_uri],
         code_verifier: PKCE_VERIFIER)

    assert last_response.status == 200
    assert_includes calls, [PKCE_VERIFIER, PKCE_VERIFIER],
                    "plain PKCE verifier check did not route through timing_safe_eql?"
  end

  def test_token_authorization_code_required_pkce_no_code_verifier
    rodauth do
      oauth_require_pkce true
    end
    setup_application

    post("/token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
    assert json_body["error_description"] == "code challenge required"
  end

  private

  def setup_application
    super
    header "Accept", "application/json"
  end

  def oauth_feature
    :oauth_pkce
  end
end
