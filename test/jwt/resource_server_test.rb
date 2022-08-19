# frozen_string_literal: true

require "test_helper"
require "webmock/minitest"

class RodauthOAuthJwtResourceServerTest < JWTIntegration
  include Rack::Test::Methods
  include WebMock::API

  def test_token_access_private_no_token
    setup_application

    header "Accept", "application/json"
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_inactive_token
    setup_application("https://auth-server-inactive-token")
    rsa_private = OpenSSL::PKey::RSA.generate 2048
    rsa_public = rsa_private.public_key
    stub_request(:get, "https://auth-server-inactive-token/.well-known/oauth-authorization-server")
      .to_return(
        headers: { "Expires" => (Time.now + 3600).httpdate },
        body: JSON.dump(jwks_uri: "https://auth-server/jwks-uri-inactive.json")
      )
    stub_request(:get, "https://auth-server/jwks-uri-inactive.json")
      .to_return(
        headers: { "Expires" => (Time.now + 3600).httpdate },
        body: JSON.dump(keys: [JWT::JWK.new(rsa_public).export.merge(use: "sig", alg: "RS256")])
      )

    token = generate_access_token(rsa_private, "RS256", iss: "https://auth-server-inactive-token", expires_in: Time.now.to_i - 3600)

    header "Accept", "application/json"
    header "Authorization", "Bearer #{token}"

    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_invalid_scope
    setup_application("https://auth-server-invalid-scope")
    rsa_private = OpenSSL::PKey::RSA.generate 2048
    rsa_public = rsa_private.public_key

    stub_request(:get, "https://auth-server-invalid-scope/.well-known/oauth-authorization-server")
      .to_return(
        headers: { "Cache-Control" => "max-age=3600" },
        body: JSON.dump(jwks_uri: "https://auth-server/jwks-uri-invalid-scope.json")
      )
      .times(1)

    stub_request(:get, "https://auth-server/jwks-uri-invalid-scope.json")
      .to_return(
        headers: { "Cache-Control" => "max-age=3600" },
        body: JSON.dump(keys: [JWT::JWK.new(rsa_public).export.merge(use: "sig", alg: "RS256")])
      )

    token = generate_access_token(rsa_private, "RS256", iss: "https://auth-server-invalid-scope", scope: "profile.write")

    header "Accept", "application/json"
    header "Authorization", "Bearer #{token}"
    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_valid_token
    setup_application("https://auth-server-valid-token")

    rsa_private = OpenSSL::PKey::RSA.generate 2048
    rsa_public = rsa_private.public_key

    stub_request(:get, "https://auth-server-valid-token/.well-known/oauth-authorization-server")
      .to_return(
        headers: { "Cache-Control" => "max-age=3600" },
        body: JSON.dump(jwks_uri: "https://auth-server/jwks-uri-valid-token.json")
      )
      .times(1)

    stub_request(:get, "https://auth-server/jwks-uri-valid-token.json")
      .to_return(
        headers: { "Cache-Control" => "max-age=3600" },
        body: JSON.dump(keys: [JWT::JWK.new(rsa_public).export.merge(use: "sig", alg: "RS256")])
      )

    token = generate_access_token(rsa_private, "RS256", iss: "https://auth-server-valid-token", scope: "profile.read")

    header "Accept", "application/json"
    header "Authorization", "Bearer #{token}"

    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  def test_token_access_private_auth_server_with_path
    setup_application("https://auth-server-valid-token/oauth")

    rsa_private = OpenSSL::PKey::RSA.generate 2048
    rsa_public = rsa_private.public_key

    stub_request(:get, "https://auth-server-valid-token/.well-known/oauth-authorization-server")
      .to_return(
        headers: { "Cache-Control" => "max-age=3600" },
        body: JSON.dump(jwks_uri: "https://auth-server/oauth/jwks-uri-valid-token.json")
      )
      .times(1)

    stub_request(:get, "https://auth-server/oauth/jwks-uri-valid-token.json")
      .to_return(
        headers: { "Cache-Control" => "max-age=3600" },
        body: JSON.dump(keys: [JWT::JWK.new(rsa_public).export.merge(use: "sig", alg: "RS256")])
      )

    token = generate_access_token(rsa_private, "RS256", iss: "https://auth-server-valid-token/oauth", scope: "profile.read")

    header "Accept", "application/json"
    header "Authorization", "Bearer #{token}"

    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  private

  def generate_access_token(priv_key, alg, params = {})
    exp = oauth_token[:expires_in]
    exp = Time.parse(oauth_token[:expires_in]) unless exp.is_a?(Time)
    params = {
      sub: oauth_token[:account_id],
      iss: "https://auth-server", # issuer
      iat: Time.now.to_i, # issued at
      client_id: oauth_application[:client_id],
      exp: exp.to_i,
      aud: "resource-server",
      scope: oauth_token[:scopes]
    }.merge(params)

    headers = {}
    jwk = JWT::JWK.new(priv_key)
    headers[:kid] = jwk.kid
    key = jwk.keypair

    params[:jti] = Digest::SHA256.hexdigest("#{params[:aud]}:#{params[:iat]}")

    JWT.encode(params, key, alg, headers)
  end

  def setup_application(auth_url = "https://auth-server")
    resource_server = Class.new(Roda)

    resource_server.plugin :rodauth do
      enable :oauth_jwt
      oauth_jwt_token_issuer auth_url
      oauth_jwt_audience "resource-server"
      is_authorization_server? false
      authorization_server_url auth_url
    end

    resource_server.route do |r|
      rodauth.require_oauth_authorization("profile.read")
      r.get "private" do
        r.get do
          "Authorized"
        end
      end
    end
    self.app = resource_server
  end
end
