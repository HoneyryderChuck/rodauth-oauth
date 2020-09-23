# frozen_string_literal: true

require "test_helper"

class RodauthOAuthRefreshTokenTest < RodaIntegration
  include Rack::Test::Methods

  def test_token_refresh_token_no_token
    setup_application
    post("/token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "refresh_token",
         refresh_token: "CODE")

    assert last_response.status == 400
    assert json_body["error"] == "invalid_grant"
  end

  def test_token_refresh_token_revoked_token
    setup_application
    oauth_token = oauth_token(revoked_at: Time.now)

    post("/token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "refresh_token",
         refresh_token: oauth_token[:refresh_token])

    assert last_response.status == 400
    assert json_body["error"] == "invalid_grant"
  end

  def test_token_refresh_token_no_client_secret
    setup_application

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "refresh_token",
         refresh_token: oauth_token[:refresh_token])

    assert last_response.status == 401
    assert json_body["error"] == "invalid_client"
  end

  def test_token_refresh_token_successful
    setup_application

    prev_token = oauth_token[:token]
    prev_expires_in = oauth_token[:expires_in]

    post("/token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "refresh_token",
         refresh_token: oauth_token[:refresh_token])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_tokens].count == 1

    verify_refresh_token_response(json_body, oauth_token)
  end

  def test_token_refresh_token_hash_columns_successful
    rodauth do
      oauth_tokens_token_hash_column :token_hash
      oauth_tokens_refresh_token_hash_column :refresh_token_hash
    end
    setup_application

    prev_token = oauth_token(refresh_token_hash: generate_hashed_token("REFRESH_TOKEN"))

    post("/token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "refresh_token",
         refresh_token: "REFRESH_TOKEN")

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_tokens].count == 1

    oauth_token = db[:oauth_tokens].first

    verify_refresh_token_response(json_body, prev_token)
    assert prev_token[:token_hash] != oauth_token[:token_hash]
  end

  def test_token_refresh_token_protection_policy_none_successful
    setup_application

    post("/token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "refresh_token",
         refresh_token: oauth_token[:refresh_token])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_tokens].count == 1

    verify_refresh_token_response(json_body, oauth_token)
  end

  private

  def setup_application
    super
    header "Accept", "application/json"
  end
end
