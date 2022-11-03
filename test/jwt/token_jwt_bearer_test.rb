# frozen_string_literal: true

require "test_helper"

class RodauthOauthJWTTokenJwtBearerTest < JWTIntegration
  include Rack::Test::Methods

  def test_oauth_jwt_bearer_as_authorization_grant_invalid_scope
    rodauth do
      oauth_jwt_keys("HS256" => "SECRET")
    end
    setup_application

    post("/token",
         grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
         scope: "bla",
         assertion: jwt_assertion(account[:email], "HS256", "SECRET"))

    verify_response(400)
    assert json_body["error"] == "invalid_scope"
  end

  def test_oauth_jwt_bearer_as_authorization_grant
    rodauth do
      oauth_jwt_keys("HS256" => "SECRET")
    end
    setup_application

    post("/token",
         grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
         assertion: jwt_assertion(account[:email], "HS256", "SECRET"))

    verify_response

    jwt_token = json_body["access_token"]

    # use token
    header "Authorization", "Bearer #{jwt_token}"

    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  def test_oauth_jwt_bearer_as_authorization_grant_with_scope
    rodauth do
      oauth_jwt_keys("HS256" => "SECRET")
    end
    setup_application

    post("/token",
         grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
         scope: "user.read",
         assertion: jwt_assertion(account[:email], "HS256", "SECRET"))

    verify_response

    jwt_token = json_body["access_token"]

    # use token
    header "Authorization", "Bearer #{jwt_token}"

    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  def test_oauth_jwt_bearer_as_client_secret_jwt_not_supported_by_application
    setup_application(:oauth_authorization_code_grant)

    oauth_application = set_oauth_application(client_id: "ID2", client_secret: "SECRET", token_endpoint_auth_method: "client_secret_basic")
    grant = set_oauth_grant(type: "authorization_code", oauth_application_id: oauth_application[:id])

    post("/token",
         client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
         client_assertion: jwt_assertion(oauth_application[:client_id], "HS256", "SECRET"),
         grant_type: "authorization_code",
         code: grant[:code],
         redirect_uri: grant[:redirect_uri])

    assert last_response.status == 401
  end

  def test_oauth_jwt_bearer_as_client_secret_jwt_not_from_application
    setup_application(:oauth_authorization_code_grant)

    oauth_application(client_secret: "SECRET", token_endpoint_auth_method: "client_secret_jwt")
    grant = set_oauth_grant(type: "authorization_code")

    post("/token",
         client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
         client_assertion: jwt_assertion(oauth_application[:client_id], "HS256", "SECRET"),
         grant_type: "authorization_code",
         client_id: "SMTHELSE",
         code: grant[:code],
         redirect_uri: grant[:redirect_uri])

    assert last_response.status == 400
    assert json_body["error"] == "invalid_grant"
  end

  def test_oauth_jwt_bearer_as_client_secret_jwt_none_alg
    rodauth do
      oauth_jwt_keys("none" => nil)
    end
    setup_application(:oauth_authorization_code_grant)

    oauth_application = set_oauth_application(client_id: "ID2", client_secret: "SECRET", token_endpoint_auth_method: "client_secret_jwt")
    grant = set_oauth_grant(type: "authorization_code", oauth_application_id: oauth_application[:id])

    post("/token",
         client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
         client_assertion: jwt_assertion(oauth_application[:client_id], "none"),
         grant_type: "authorization_code",
         code: grant[:code],
         redirect_uri: grant[:redirect_uri])

    verify_response(401)
  end

  def test_oauth_jwt_bearer_as_client_secret_jwt
    rodauth do
      oauth_jwt_keys("RS256" => OpenSSL::PKey::RSA.generate(2048))
    end
    setup_application(:oauth_authorization_code_grant)

    oauth_application = oauth_application(client_id: "ID2", client_secret: "SECRET", token_endpoint_auth_method: "client_secret_jwt")
    grant = set_oauth_grant(type: "authorization_code", oauth_application_id: oauth_application[:id])

    post("/token",
         client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
         client_assertion: jwt_assertion(oauth_application[:client_id], "HS256", "SECRET"),
         grant_type: "authorization_code",
         code: grant[:code],
         redirect_uri: grant[:redirect_uri])

    verify_response

    jwt_token = json_body["access_token"]

    # use token
    header "Authorization", "Bearer #{jwt_token}"

    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  def test_oauth_jwt_bearer_as_private_key_jwt_not_supported_by_application
    setup_application(:oauth_authorization_code_grant)

    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    oauth_application = set_oauth_application(
      client_id: "ID2",
      jwks: JSON.dump([JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256")]),
      token_endpoint_auth_method: "client_secret_basic"
    )
    grant = set_oauth_grant(type: "authorization_code", oauth_application_id: oauth_application[:id])

    post("/token",
         client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
         client_assertion: jwt_assertion(oauth_application[:client_id], "RS256", jws_key),
         grant_type: "authorization_code",
         code: grant[:code],
         redirect_uri: grant[:redirect_uri])

    assert last_response.status == 401
  end

  def test_oauth_jwt_bearer_as_private_key_jwt_not_from_application
    setup_application(:oauth_authorization_code_grant)

    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    oauth_application(client_secret: "SECRET", jwks: JSON.dump([JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256")]))
    grant = set_oauth_grant(type: "authorization_code")

    post("/token",
         client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
         client_assertion: jwt_assertion(oauth_application[:client_id], "RS256", jws_key),
         grant_type: "authorization_code",
         client_id: "SMTHELSE",
         code: grant[:code],
         redirect_uri: grant[:redirect_uri])

    assert last_response.status == 400
    assert json_body["error"] == "invalid_grant"
  end

  def test_oauth_jwt_bearer_as_private_key_jwt
    rodauth do
      oauth_jwt_keys("RS256" => OpenSSL::PKey::RSA.generate(2048))
    end
    setup_application(:oauth_authorization_code_grant)

    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    oauth_application = set_oauth_application(
      client_id: "ID2",
      jwks: JSON.dump([JWT::JWK.new(jws_public_key).export.merge(use: "sig", alg: "RS256")]),
      token_endpoint_auth_method: "private_key_jwt"
    )
    grant = set_oauth_grant(type: "authorization_code", oauth_application_id: oauth_application[:id])

    post("/token",
         client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
         client_assertion: jwt_assertion(oauth_application[:client_id], "RS256", jws_key),
         grant_type: "authorization_code",
         code: grant[:code],
         redirect_uri: grant[:redirect_uri])

    verify_response

    jwt_token = json_body["access_token"]

    # use token
    header "Authorization", "Bearer #{jwt_token}"

    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  def test_oauth_jwt_bearer_as_private_key_jwt_no_kid
    rodauth do
      oauth_jwt_keys("RS256" => OpenSSL::PKey::RSA.generate(2048))
    end
    setup_application(:oauth_authorization_code_grant)

    jws_key = OpenSSL::PKey::RSA.generate(2048)
    jws_public_key = jws_key.public_key
    jwk = JWT::JWK.new(jws_public_key).export
    jwk.delete(:kid)
    oauth_application = set_oauth_application(
      client_id: "ID2",
      jwks: JSON.dump([jwk.merge(use: "sig", alg: "RS256")]),
      token_endpoint_auth_method: "private_key_jwt"
    )
    grant = set_oauth_grant(type: "authorization_code", oauth_application_id: oauth_application[:id])

    post("/token",
         client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
         client_assertion: jwt_assertion(oauth_application[:client_id], "RS256", jws_key),
         grant_type: "authorization_code",
         code: grant[:code],
         redirect_uri: grant[:redirect_uri])

    verify_response

    jwt_token = json_body["access_token"]

    # use token
    header "Authorization", "Bearer #{jwt_token}"

    # valid token, and now we're getting somewhere
    get("/private")
    assert last_response.status == 200
  end

  private

  def oauth_feature
    :oauth_jwt_bearer_grant
  end

  def default_grant_type
    "jwt-bearer"
  end

  def jwt_assertion(principal, algo, signing_key = nil, extra_claims = {})
    claims = {
      iss: oauth_application[:client_id],
      aud: "http://example.org/token",
      sub: principal,
      iat: Time.now.to_i, # issued at
      exp: Time.now.to_i + 3600
    }.merge(extra_claims)

    headers = {}

    if signing_key
      jwk = JWT::JWK.new(signing_key)
      headers[:kid] = jwk.kid

      signing_key = jwk.keypair
    end

    JWT.encode(claims, signing_key, algo, headers)
  end

  def setup_application(*)
    super
    header "Accept", "application/json"
  end
end
