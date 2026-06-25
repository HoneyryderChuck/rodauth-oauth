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

    token = generate_access_token(rsa_private, "RS256", iss: "https://auth-server-inactive-token", scope: "profile.read",
                                                        exp: Time.now.to_i - 3600)

    header "Accept", "application/json"
    header "Authorization", "Bearer #{token}"

    get("/private")
    assert last_response.status == 401
  end

  # Regression tests for independent JWT claim verification in jwt_decode. These primarily guard
  # the json-jwt decode path (run with JWT_LIB=json/jwt), where a token used to be accepted unless
  # every claim check failed at once; they are library-agnostic and pass on the ruby-jwt path too.
  # Each token is otherwise valid (good signature + scope) so only the claim under test is bad.
  def test_token_access_private_expired_exp
    setup_application("https://auth-server-expired-exp")
    rsa_private = OpenSSL::PKey::RSA.generate 2048

    stub_request(:get, "https://auth-server-expired-exp/.well-known/oauth-authorization-server")
      .to_return(
        headers: { "Cache-Control" => "max-age=3600" },
        body: JSON.dump(jwks_uri: "https://auth-server/jwks-uri-expired-exp.json")
      )
      .times(1)
    stub_request(:get, "https://auth-server/jwks-uri-expired-exp.json")
      .to_return(
        headers: { "Cache-Control" => "max-age=3600" },
        body: JSON.dump(keys: [JWT::JWK.new(rsa_private.public_key).export.merge(use: "sig", alg: "RS256")])
      )

    token = generate_access_token(rsa_private, "RS256", iss: "https://auth-server-expired-exp", scope: "profile.read",
                                                        exp: Time.now.to_i - 3600)

    header "Accept", "application/json"
    header "Authorization", "Bearer #{token}"

    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_future_nbf
    setup_application("https://auth-server-future-nbf")
    rsa_private = OpenSSL::PKey::RSA.generate 2048

    stub_request(:get, "https://auth-server-future-nbf/.well-known/oauth-authorization-server")
      .to_return(
        headers: { "Cache-Control" => "max-age=3600" },
        body: JSON.dump(jwks_uri: "https://auth-server/jwks-uri-future-nbf.json")
      )
      .times(1)
    stub_request(:get, "https://auth-server/jwks-uri-future-nbf.json")
      .to_return(
        headers: { "Cache-Control" => "max-age=3600" },
        body: JSON.dump(keys: [JWT::JWK.new(rsa_private.public_key).export.merge(use: "sig", alg: "RS256")])
      )

    token = generate_access_token(rsa_private, "RS256", iss: "https://auth-server-future-nbf", scope: "profile.read",
                                                        nbf: Time.now.to_i + 3600)

    header "Accept", "application/json"
    header "Authorization", "Bearer #{token}"

    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_future_iat
    setup_application("https://auth-server-future-iat")
    rsa_private = OpenSSL::PKey::RSA.generate 2048

    stub_request(:get, "https://auth-server-future-iat/.well-known/oauth-authorization-server")
      .to_return(
        headers: { "Cache-Control" => "max-age=3600" },
        body: JSON.dump(jwks_uri: "https://auth-server/jwks-uri-future-iat.json")
      )
      .times(1)
    stub_request(:get, "https://auth-server/jwks-uri-future-iat.json")
      .to_return(
        headers: { "Cache-Control" => "max-age=3600" },
        body: JSON.dump(keys: [JWT::JWK.new(rsa_private.public_key).export.merge(use: "sig", alg: "RS256")])
      )

    # iat far in the future (beyond oauth_jwt_iat_leeway) must be rejected
    token = generate_access_token(rsa_private, "RS256", iss: "https://auth-server-future-iat", scope: "profile.read",
                                                        iat: Time.now.to_i + 3600)

    header "Accept", "application/json"
    header "Authorization", "Bearer #{token}"

    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_future_iat_within_leeway
    setup_application("https://auth-server-iat-leeway")
    rsa_private = OpenSSL::PKey::RSA.generate 2048

    stub_request(:get, "https://auth-server-iat-leeway/.well-known/oauth-authorization-server")
      .to_return(
        headers: { "Cache-Control" => "max-age=3600" },
        body: JSON.dump(jwks_uri: "https://auth-server/jwks-uri-iat-leeway.json")
      )
      .times(1)
    stub_request(:get, "https://auth-server/jwks-uri-iat-leeway.json")
      .to_return(
        headers: { "Cache-Control" => "max-age=3600" },
        body: JSON.dump(keys: [JWT::JWK.new(rsa_private.public_key).export.merge(use: "sig", alg: "RS256")])
      )

    # iat slightly in the future, within the default oauth_jwt_iat_leeway (30s), is tolerated as clock skew
    token = generate_access_token(rsa_private, "RS256", iss: "https://auth-server-iat-leeway", scope: "profile.read",
                                                        iat: Time.now.to_i + 5)

    header "Accept", "application/json"
    header "Authorization", "Bearer #{token}"

    get("/private")
    # oauth_jwt_iat_leeway is now honored on BOTH backends (json-jwt and ruby-jwt), so a future iat
    # within the leeway window is accepted regardless of the active JWT library.
    assert last_response.status == 200
  end

  def test_token_access_private_wrong_iss
    setup_application("https://auth-server-wrong-iss")
    rsa_private = OpenSSL::PKey::RSA.generate 2048

    stub_request(:get, "https://auth-server-wrong-iss/.well-known/oauth-authorization-server")
      .to_return(
        headers: { "Cache-Control" => "max-age=3600" },
        body: JSON.dump(jwks_uri: "https://auth-server/jwks-uri-wrong-iss.json")
      )
      .times(1)
    stub_request(:get, "https://auth-server/jwks-uri-wrong-iss.json")
      .to_return(
        headers: { "Cache-Control" => "max-age=3600" },
        body: JSON.dump(keys: [JWT::JWK.new(rsa_private.public_key).export.merge(use: "sig", alg: "RS256")])
      )

    # iss differs from the resource server's authorization_server_url
    token = generate_access_token(rsa_private, "RS256", iss: "https://evil-issuer", scope: "profile.read")

    header "Accept", "application/json"
    header "Authorization", "Bearer #{token}"

    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_wrong_aud
    setup_application("https://auth-server-wrong-aud")
    rsa_private = OpenSSL::PKey::RSA.generate 2048

    stub_request(:get, "https://auth-server-wrong-aud/.well-known/oauth-authorization-server")
      .to_return(
        headers: { "Cache-Control" => "max-age=3600" },
        body: JSON.dump(jwks_uri: "https://auth-server/jwks-uri-wrong-aud.json")
      )
      .times(1)
    stub_request(:get, "https://auth-server/jwks-uri-wrong-aud.json")
      .to_return(
        headers: { "Cache-Control" => "max-age=3600" },
        body: JSON.dump(keys: [JWT::JWK.new(rsa_private.public_key).export.merge(use: "sig", alg: "RS256")])
      )

    # aud differs from the application's client_id; client_id stays valid so only aud is wrong
    token = generate_access_token(rsa_private, "RS256", iss: "https://auth-server-wrong-aud", scope: "profile.read",
                                                        aud: "WRONG_AUDIENCE")

    header "Accept", "application/json"
    header "Authorization", "Bearer #{token}"

    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_invalid_jti
    setup_application("https://auth-server-invalid-jti")
    rsa_private = OpenSSL::PKey::RSA.generate 2048

    stub_request(:get, "https://auth-server-invalid-jti/.well-known/oauth-authorization-server")
      .to_return(
        headers: { "Cache-Control" => "max-age=3600" },
        body: JSON.dump(jwks_uri: "https://auth-server/jwks-uri-invalid-jti.json")
      )
      .times(1)
    stub_request(:get, "https://auth-server/jwks-uri-invalid-jti.json")
      .to_return(
        headers: { "Cache-Control" => "max-age=3600" },
        body: JSON.dump(keys: [JWT::JWK.new(rsa_private.public_key).export.merge(use: "sig", alg: "RS256")])
      )

    # jti is deterministically SHA256("aud:iat"); override it with a value that can't match
    token = generate_access_token(rsa_private, "RS256", iss: "https://auth-server-invalid-jti", scope: "profile.read",
                                                        jti: "tampered-jti")

    header "Accept", "application/json"
    header "Authorization", "Bearer #{token}"

    get("/private")
    assert last_response.status == 401
  end

  def test_token_access_private_valid_claims
    setup_application("https://auth-server-valid-claims")
    rsa_private = OpenSSL::PKey::RSA.generate 2048

    stub_request(:get, "https://auth-server-valid-claims/.well-known/oauth-authorization-server")
      .to_return(
        headers: { "Cache-Control" => "max-age=3600" },
        body: JSON.dump(jwks_uri: "https://auth-server/jwks-uri-valid-claims.json")
      )
      .times(1)
    stub_request(:get, "https://auth-server/jwks-uri-valid-claims.json")
      .to_return(
        headers: { "Cache-Control" => "max-age=3600" },
        body: JSON.dump(keys: [JWT::JWK.new(rsa_private.public_key).export.merge(use: "sig", alg: "RS256")])
      )

    token = generate_access_token(rsa_private, "RS256", iss: "https://auth-server-valid-claims", scope: "profile.read",
                                                        exp: Time.now.to_i + 3600)

    header "Accept", "application/json"
    header "Authorization", "Bearer #{token}"

    get("/private")
    assert last_response.status == 200
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
    exp = oauth_grant[:expires_in]
    exp = Time.parse(oauth_grant[:expires_in]) unless exp.is_a?(Time)
    params = {
      sub: oauth_grant[:account_id],
      iss: "https://auth-server", # issuer
      iat: Time.now.to_i, # issued at
      client_id: oauth_application[:client_id],
      exp: exp.to_i,
      aud: oauth_application[:client_id],
      scope: oauth_grant[:scopes]
    }.merge(params)

    headers = { typ: "at+jwt" }
    jwk = JWT::JWK.new(priv_key)
    headers[:kid] = jwk.kid
    key = jwk.keypair

    params[:jti] ||= Digest::SHA256.hexdigest("#{params[:aud]}:#{params[:iat]}")

    JWT.encode(params, key, alg, headers)
  end

  def setup_application(auth_url = "https://auth-server")
    resource_server = Class.new(Roda)
    resource_server.plugin :common_logger if ENV.key?("RODAUTH_DEBUG")

    resource_server.plugin :rodauth do
      enable :oauth_resource_server, :oauth_jwt
      authorization_server_url auth_url

      http_request_cache do
        obj = Object.new
        obj.define_singleton_method(:[]) { |*|; } # rubocop:disable Lint/EmptyBlock
        obj.define_singleton_method(:set) do |*, &blk|
          body, _ttl = blk.call
          body
        end
        obj
      end
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
