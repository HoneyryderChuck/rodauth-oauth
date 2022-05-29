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

  def test_token_refresh_token_same_code
    rodauth do
      oauth_unique_id_generator { "TOKEN" }
    end
    setup_application
    login

    _prev_token = oauth_token(token: "TOKEN")
    @oauth_token = nil
    token = oauth_token(token: "OLD_TOKEN", refresh_token: "OTHER_REFRESH_TOKEN", scopes: "user.read")

    post("/token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "refresh_token",
         refresh_token: token[:refresh_token])

    assert last_response.status == 409
    assert last_response.headers["Content-Type"] == "application/json"
    assert json_body["error"] == "invalid_request"
    assert json_body["error_description"] == "error generating unique token"
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

    post("/token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "refresh_token",
         refresh_token: oauth_token[:refresh_token])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_tokens].where(revoked_at: nil).count == 1

    verify_refresh_token_response(json_body, oauth_token)
  end

  def test_token_refresh_token_hash_columns_successful
    rodauth do
      oauth_tokens_token_hash_column :token_hash
      oauth_tokens_refresh_token_hash_column :refresh_token_hash
    end
    setup_application

    prev_token = oauth_token(refresh_token: nil, refresh_token_hash: generate_hashed_token("REFRESH_TOKEN"))

    post("/token",
         client_secret: "CLIENT_SECRET",
         client_id: oauth_application[:client_id],
         grant_type: "refresh_token",
         refresh_token: "REFRESH_TOKEN")

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_tokens].where(revoked_at: nil).count == 1

    oauth_token = db[:oauth_tokens].first

    verify_refresh_token_response(json_body, prev_token)
    assert json_body["refresh_token"] == "REFRESH_TOKEN"
    assert prev_token[:token_hash] != oauth_token[:token_hash]
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

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert db[:oauth_tokens].where(revoked_at: nil).count == 1

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

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    # previous token gets revoked
    assert db[:oauth_tokens].count == 2
    assert db[:oauth_tokens].where(revoked_at: nil).count == 1

    new_token = db[:oauth_tokens].where(revoked_at: nil).first
    assert new_token[:access_token] == json_body["token"]
    assert new_token[:refresh_token] == json_body["refresh_token"]

    verify_refresh_token_response(json_body, oauth_token)
    assert json_body["refresh_token"] != oauth_token[:refresh_token]

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

    assert db[:oauth_tokens].where(revoked_at: nil).count.zero?
  end

  private

  def setup_application
    super
    header "Accept", "application/json"
  end
end
