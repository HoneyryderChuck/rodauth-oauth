# frozen_string_literal: true

require "test_helper"

class RodauthOAuthOIDCTokenUserInfoTest < OIDCIntegration
  include Rack::Test::Methods

  def test_oidc_userinfo_openid
    setup_application

    access_token = generate_access_token("openid")
    login(access_token)

    @json_body = nil
    get("/userinfo")

    assert last_response.status == 200
    assert json_body.key?("sub")
  end

  def test_oidc_userinfo_email
    setup_application

    access_token = generate_access_token("openid email")
    login(access_token)

    @json_body = nil
    # valid token, and now we're getting somewhere
    get("/userinfo")

    assert last_response.status == 200
    assert json_body.key?("sub")
    assert json_body.key?("email")
    assert json_body["email_verified"] == true
  end

  def test_oidc_userinfo_email_email
    setup_application

    access_token = generate_access_token("openid email.email")
    login(access_token)

    @json_body = nil
    # valid token, and now we're getting somewhere
    get("/userinfo")

    assert last_response.status == 200
    assert json_body.key?("sub")
    assert json_body.key?("email")
    assert !json_body.key?("email_verified")
  end

  def test_oidc_userinfo_address
    setup_application

    access_token = generate_access_token("openid address")
    login(access_token)

    @json_body = nil
    # valid token, and now we're getting somewhere
    get("/userinfo")

    assert last_response.status == 200
    assert json_body.key?("sub")
    assert json_body.key?("address")
    assert json_body["address"]["formatted"] == "Rue de ancien regime"
    assert json_body["address"]["country"] == "Babylon"
  end

  def test_oidc_userinfo_additional_claims
    setup_application

    access_token = generate_access_token("openid fruit")
    login(access_token)

    @json_body = nil
    # valid token, and now we're getting somewhere
    get("/userinfo")

    assert last_response.status == 200
    assert json_body.key?("sub")
    assert json_body.key?("fruit")
    assert json_body["fruit"] == "tutti-frutti"
  end

  def test_oidc_userinfo_userinfo_signed_response_alg
    jws_rs256_key = OpenSSL::PKey::RSA.generate(2048)
    jws_rs512_key = OpenSSL::PKey::RSA.generate(2048)
    jws_rs512_public_key = jws_rs512_key.public_key
    rodauth do
      oauth_jwt_keys { { "RS256" => jws_rs256_key, "RS512" => jws_rs512_key } }
      oauth_jwt_key { oauth_jwt_keys["RS256"] }
      oauth_jwt_algorithm "RS256"
    end
    setup_application
    oauth_application(userinfo_signed_response_alg: "RS512")

    access_token = generate_access_token("openid fruit")
    login(access_token)

    @json_body = nil
    # valid token, and now we're getting somewhere
    get("/userinfo")

    assert last_response.status == 200

    begin
      json_body = JWT.decode(last_response.body, jws_rs512_public_key, true, { "algorithm" => "RS512" }).first
      assert true
    rescue JWT::DecodeError
      assert false
    end

    assert json_body.key?("sub")
    assert json_body.key?("fruit")
  end

  private

  def setup_application
    rodauth do
      oauth_jwt_key "SECRET"
      oauth_jwt_algorithm "HS256"
      get_oidc_param do |account, claim|
        case claim
        when :email_verified
          account[:status_id] == account_open_status_value
        when :formatted
          "Rue de ancien regime"
        when :country
          "Babylon"
        else
          account[claim]
        end
      end
      get_additional_param do |_account, claim|
        case claim
        when :fruit
          "tutti-frutti"
        end
      end
    end

    super
  end

  # overriding to implement the client/secret basic authorization
  def login(token)
    header "Authorization", "Bearer #{token}"
  end

  def generate_access_token(scopes = "openid")
    grant = oauth_grant(scopes: scopes)

    post("/token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: grant[:code],
         redirect_uri: grant[:redirect_uri])

    verify_response

    verify_oauth_token
    json_body["access_token"]
  end
end
