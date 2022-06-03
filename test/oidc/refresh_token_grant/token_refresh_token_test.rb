# frozen_string_literal: true

require "test_helper"

class RodauthOAuthOIDCRefreshTokenTest < OIDCIntegration
  include Rack::Test::Methods

  def test_token_refresh_token_revoked_token
    setup_application
    oauth_token = oauth_token(revoked_at: Sequel::CURRENT_TIMESTAMP)

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

  def test_token_refresh_token_expired_token
    rodauth do
      oauth_refresh_token_expires_in 2 # 2 sec
    end
    setup_application

    short_lived_token = oauth_token(expires_in: Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, seconds: 3)) # expired 3 secs ago
    # first request works
    post("/token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "refresh_token",
         refresh_token: short_lived_token[:refresh_token])

    assert last_response.status == 400
    assert last_response.headers["Content-Type"] == "application/json"
    assert json_body["error"] == "invalid_grant"
    assert json_body["error_description"] == "Invalid grant"
  end

  def test_token_refresh_token_successful
    setup_application

    oauth_token = set_oauth_token

    post("/token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "refresh_token",
         refresh_token: oauth_token[:refresh_token])

    verify_response
    verify_access_token_response(json_body, oauth_token, "SECRET", "HS256")
    verify_refresh_token_response(json_body, oauth_token)
    assert json_body["refresh_token"] == oauth_token[:refresh_token]
  end

  def test_token_refresh_token_hash_columns_successful
    rodauth do
      oauth_tokens_refresh_token_hash_column :refresh_token_hash
    end
    setup_application

    prev_token = oauth_token(refresh_token: nil, refresh_token_hash: generate_hashed_token("REFRESH_TOKEN"))

    post("/token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "refresh_token",
         refresh_token: "REFRESH_TOKEN")

    verify_response
    # oauth_token = verify_oauth_token
    verify_access_token_response(json_body, oauth_token, "SECRET", "HS256")
    verify_refresh_token_response(json_body, prev_token)
    assert json_body["refresh_token"] == "REFRESH_TOKEN"
    assert prev_token[:refresh_token_hash] == oauth_token[:refresh_token_hash]
  end

  def test_token_refresh_token_protection_policy_none_successful
    rodauth do
      oauth_refresh_token_protection_policy "none"
    end
    setup_application

    post("/token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "refresh_token",
         refresh_token: oauth_token[:refresh_token])

    verify_response
    # oauth_token = verify_oauth_token
    verify_access_token_response(json_body, oauth_token, "SECRET", "HS256")
    verify_refresh_token_response(json_body, oauth_token)
    assert json_body["refresh_token"] == oauth_token[:refresh_token]
  end

  def test_token_refresh_token_protection_policy_rotation
    rodauth do
      oauth_refresh_token_protection_policy "rotation"
    end
    setup_application

    # generates a new token registered in the db
    post("/token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "refresh_token",
         refresh_token: oauth_token[:refresh_token])

    verify_response
    verify_refresh_token_response(json_body, oauth_token)
    assert json_body["refresh_token"] != oauth_token[:refresh_token]

    # previous token gets revoked
    assert db[:oauth_tokens].count == 1

    verify_access_token_response(json_body, oauth_token, "SECRET", "HS256")

    # invalidates all tokens generated from that token
    @json_body = nil
    post("/token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "refresh_token",
         refresh_token: oauth_token[:refresh_token])

    assert last_response.status == 400
    assert last_response.headers["Content-Type"] == "application/json"
    assert json_body["error"] == "invalid_grant"
    assert json_body["error_description"] == "Invalid grant"
  end

  private

  def setup_application
    rodauth do
      oauth_jwt_key "SECRET"
      oauth_jwt_algorithm "HS256"
    end
    super
    header "Accept", "application/json"
  end
end
