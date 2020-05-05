# frozen_string_literal: true

require "test_helper"

class RodaOauthTokenTest < Minitest::Test
  include Capybara::DSL
  include Rack::Test::Methods 

  def test_token_no_params
  	setup_application
  	post("/oauth-token")

    assert last_response.status == 400 
    json_body = JSON.parse(last_response.body)
    assert json_body["error"] == "invalid_request"
  end

  def test_token_no_grant
    setup_application
    post("/oauth-token", client_id: oauth_application[:client_id], grant_type: "authorization_code", code: "CODE")

    assert last_response.status == 400 
    json_body = JSON.parse(last_response.body)
    assert json_body["error"] == "invalid_grant"
  end

  def test_token_expired_grant
    setup_application
    grant = oauth_grant(expires_in: Time.now - 60) 

    post("/oauth-token", client_id: oauth_application[:client_id], grant_type: "authorization_code", code: grant[:code], redirect_uri: grant[:callback_url])

    assert last_response.status == 400 
    json_body = JSON.parse(last_response.body)
    assert json_body["error"] == "invalid_grant"
  end

    def test_token_revoked_grant
    setup_application
    grant = oauth_grant(revoked_at: Time.now) 

    post("/oauth-token", client_id: oauth_application[:client_id], grant_type: "authorization_code", code: grant[:code], redirect_uri: grant[:callback_url])

    assert last_response.status == 400 
    json_body = JSON.parse(last_response.body)
    assert json_body["error"] == "invalid_grant"
  end

  def test_token_successful
    setup_application

    post("/oauth-token", client_id: oauth_application[:client_id], grant_type: "authorization_code", code: oauth_grant[:code], redirect_uri: oauth_grant[:callback_url])

    assert last_response.status == 200
    assert last_response.headers["Content-Type"] == "application/json"

    assert DB[:oauth_tokens].count == 1

    access_token = DB[:oauth_tokens].first

    oauth_grant = DB[:oauth_grants].where(id: access_token[:oauth_grant_id]).first
    assert !oauth_grant[:revoked_at].nil?, "oauth grant should be revoked"

    json_body = JSON.parse(last_response.body)
    assert json_body["token"] == access_token[:token]
    assert json_body["refresh_token"] == access_token[:refresh_token]
    assert !json_body["expires_in"].nil?
  end

  private

  def setup_application
    rodauth do
      enable :oauth
      password_match? do |_password|
        true
      end
    end
    roda do |r|
      r.rodauth

      r.root do
        flash["error"] || flash["notice"] || "Unauthorized"
      end

      rodauth.oauth_authorize

      r.on "private" do
        r.get do
          flash["error"] || flash["notice"] || "Authorized"
        end
      end
    end
  end
end
