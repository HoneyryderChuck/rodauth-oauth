# frozen_string_literal: true

require "test_helper"

class RodauthOauthOIDCTokenAuthorizationCodeTest < OIDCIntegration
  include Rack::Test::Methods

  def test_oidc_authorization_code_email_scope
    rodauth do
      oauth_jwt_key "SECRET"
      oauth_jwt_algorithm "HS256"

      get_oidc_param do |token, param|
        @account ||= begin
          account_id = token[:account_id]
          db[:accounts].where(id: account_id).first
          # TODO: raise error? otherwise?
        end

        case param
        when :email
          @account[:email]
        when :email_verified
          @account[:status_id] == 2
        end
      end
    end
    setup_application

    grant = oauth_grant(scopes: "openid email")

    post("/oauth-token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: grant[:code],
         redirect_uri: grant[:redirect_uri])

    verify_response

    oauth_token = verify_oauth_token

    verify_response_body(json_body, oauth_token, "SECRET", "HS256")

    id_claims, = JWT.decode(json_body["id_token"], "SECRET", true, algorithms: %w[HS256])

    assert id_claims.key?("email")
    assert id_claims["email"] == account[:email]
    assert id_claims.key?("email_verified")
    assert id_claims["email_verified"] == true
  end

  def test_oidc_authorization_code_hmac_sha256
    rodauth do
      oauth_jwt_key "SECRET"
      oauth_jwt_algorithm "HS256"
    end
    setup_application

    post("/oauth-token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    verify_response

    oauth_token = verify_oauth_token

    verify_response_body(json_body, oauth_token, "SECRET", "HS256")
  end

  def test_oidc_authorization_code_jws_rsa_sha256
    rsa_private = OpenSSL::PKey::RSA.generate 2048
    rsa_public = rsa_private.public_key
    rodauth do
      oauth_jwt_key rsa_private
      oauth_jwt_public_key rsa_public
      oauth_jwt_algorithm "RS256"
    end
    setup_application

    post("/oauth-token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    verify_response

    oauth_token = verify_oauth_token

    verify_response_body(json_body, oauth_token, rsa_public, "RS256")
  end

  unless RUBY_ENGINE == "jruby"
    def test_oidc_authorization_code_jws_ecdsa_p256
      ecdsa_key = OpenSSL::PKey::EC.new "prime256v1"
      ecdsa_key.generate_key
      ecdsa_public = OpenSSL::PKey::EC.new ecdsa_key
      ecdsa_public.private_key = nil

      rodauth do
        oauth_jwt_key ecdsa_key
        oauth_jwt_public_key ecdsa_public
        oauth_jwt_algorithm "ES256"
      end
      setup_application

      post("/oauth-token",
           client_id: oauth_application[:client_id],
           client_secret: "CLIENT_SECRET",
           grant_type: "authorization_code",
           code: oauth_grant[:code],
           redirect_uri: oauth_grant[:redirect_uri])

      verify_response

      oauth_token = verify_oauth_token

      verify_response_body(json_body, oauth_token, ecdsa_public, "ES256")
    end
  end # jruby doesn't do ecdsa well

  def test_oidc_authorization_code_jwe
    jwe_key = OpenSSL::PKey::RSA.new(2048)

    rodauth do
      oauth_jwt_key "SECRET"
      oauth_jwt_algorithm "HS256"
      oauth_jwt_jwe_key jwe_key
      oauth_jwt_jwe_public_key jwe_key.public_key
      oauth_jwt_jwe_algorithm "RSA-OAEP"
      oauth_jwt_jwe_encryption_method "A256GCM"
    end
    setup_application

    post("/oauth-token",
         client_id: oauth_application[:client_id],
         client_secret: "CLIENT_SECRET",
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    verify_response

    oauth_token = verify_oauth_token

    encrypted_token = json_body["access_token"]
    access_token = JWE.decrypt(encrypted_token, jwe_key)

    encrypted_id_token = json_body["id_token"]
    id_token = JWE.decrypt(encrypted_id_token, jwe_key)
    verify_response_body(json_body.merge("access_token" => access_token, "id_token" => id_token), oauth_token, "SECRET", "HS256")
  end

  private

  def setup_application
    super
    header "Accept", "application/json"
  end
end
