# frozen_string_literal: true

require "test_helper"

class RodauthOAuthCertificateBoundTokenIntrospectTest < RodaIntegration
  include Rack::Test::Methods

  def test_oauth_introspect_missing_token
    setup_application

    header "Accept", "application/json"

    post_introspect
    assert last_response.status == 400
    assert json_body["error"] == "invalid_request"
  end

  def test_oauth_introspect_expired_token
    setup_application
    login

    header "Accept", "application/json"

    grant = oauth_grant_with_token(
      expires_in: Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, seconds: 20),
      certificate_thumbprint: generate_thumbprint(public_key)
    )

    # valid token, and now we're getting somewhere
    post_introspect({
                      token: grant[:token]
                    })
    assert last_response.status == 200
    assert json_body == { "active" => false }
  end

  def test_oauth_introspect_unknown_token_hint
    setup_application

    header "Accept", "application/json"

    grant = oauth_grant_with_token(
      certificate_thumbprint: generate_thumbprint(public_key)
    )

    # valid token, and now we're getting somewhere
    post_introspect({
                      token: grant[:refresh_token],
                      token_type_hint: "wups"

                    })
    assert last_response.status == 400
    assert json_body["error"] == "unsupported_token_type"
  end

  def test_oauth_introspect_access_token
    setup_application

    header "Accept", "application/json"

    grant = oauth_grant_with_token(
      certificate_thumbprint: generate_thumbprint(public_key)
    )
    # valid token, and now we're getting somewhere
    post_introspect({
                      token: grant[:token]
                    })
    assert last_response.status == 200
    assert json_body["active"] == true
    assert json_body["username"] == account[:email]
    assert json_body["scope"] == oauth_grant_with_token[:scopes]
    assert json_body["client_id"] == oauth_application[:client_id]
    assert json_body["token_type"] == "bearer"
    assert json_body.key?("exp")
  end

  def test_oauth_introspect_refresh_token
    setup_application

    header "Accept", "application/json"
    grant = oauth_grant_with_token(
      certificate_thumbprint: generate_thumbprint(public_key)
    )

    # valid token, and now we're getting somewhere
    post_introspect({
                      token: grant[:refresh_token]
                    })
    assert last_response.status == 200
    assert json_body["active"] == true
    assert json_body["username"] == account[:email]
    assert json_body["scope"] == oauth_grant_with_token[:scopes]
    assert json_body["client_id"] == oauth_application[:client_id]
    assert json_body["token_type"] == "bearer"
    assert json_body.key?("exp")
  end

  def test_oauth_introspect_refresh_token_wrong_token_hint
    setup_application

    header "Accept", "application/json"

    grant = oauth_grant_with_token(
      certificate_thumbprint: generate_thumbprint(public_key)
    )
    # valid token, and now we're getting somewhere
    post_introspect({
                      token: grant[:refresh_token],
                      token_type_hint: "access_token"
                    })
    assert last_response.status == 200
    assert json_body == { "active" => false }
  end

  def test_oauth_introspect_refresh_token_token_hint
    setup_application

    header "Accept", "application/json"

    grant = oauth_grant_with_token(
      certificate_thumbprint: generate_thumbprint(public_key)
    )
    # valid token, and now we're getting somewhere
    post_introspect({
                      token: grant[:refresh_token],
                      token_type_hint: "refresh_token"
                    })
    assert last_response.status == 200
    assert json_body["active"] == true
  end

  def test_oauth_introspect_access_token_credentials_grant
    setup_application

    header "Accept", "application/json"

    grant = oauth_grant_with_token(
      type: "client_credentials", account_id: nil,
      certificate_thumbprint: generate_thumbprint(public_key)
    )

    # valid token, and now we're getting somewhere
    post_introspect({
                      client_id: oauth_application[:client_id],
                      client_secret: "CLIENT_SECRET",
                      token: grant[:token]
                    })
    assert last_response.status == 200
    assert json_body["active"] == true
    assert json_body["username"] == "Foo"
    assert json_body["scope"] == grant[:scopes]
    assert json_body["client_id"] == oauth_application[:client_id]
    assert json_body["token_type"] == "bearer"
    assert json_body.key?("exp")
  end

  def test_oauth_introspect_access_token_client_credentials_auth
    setup_application
    header "Accept", "application/json"
    client_credentials_grant = set_oauth_grant_with_token(type: "client_credentials", account_id: nil, token: "CLIENT_TOKEN",
                                                          refresh_token: "CLIENT_REFRESH_TOKEN")
    header "Authorization", "Bearer #{client_credentials_grant[:token]}"
    grant = oauth_grant_with_token(
      certificate_thumbprint: generate_thumbprint(public_key)
    )
    # valid token, and now we're getting somewhere
    post_introspect({
                      token: grant[:token]
                    })
    assert last_response.status == 200
    assert json_body["active"] == true
    assert json_body["username"] == account[:email]
    assert json_body["scope"] == oauth_grant_with_token[:scopes]
    assert json_body["client_id"] == oauth_application[:client_id]
    assert json_body["token_type"] == "bearer"
    assert json_body.key?("exp")
  end

  private

  def private_key
    @private_key ||= OpenSSL::PKey::RSA.generate(2048)
  end

  def public_key
    @public_key ||= private_key.public_key
  end

  def public_jwk
    @public_jwk ||= JWT::JWK.new(public_key).export.merge(use: "sig", alg: "RS256")
  end

  def generate_thumbprint(key)
    jwk = JWT::JWK.new(key)
    JWT::JWK::Thumbprint.new(jwk).generate
  end

  def certificate
    @certificate ||= begin
      cert = OpenSSL::X509::Certificate.new
      name = OpenSSL::X509::Name.parse(subject)
      cert.subject = cert.issuer = name
      cert.not_before = Time.now
      cert.not_after = Time.now + (365 * 24 * 60 * 60)
      cert.public_key = public_key
      cert.serial = 0x0
      cert.version = 2

      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = cert
      ef.issuer_certificate = cert
      cert.extensions = [
        ef.create_extension("basicConstraints", "CA:TRUE", true),
        ef.create_extension("keyUsage", "keyCertSign, cRLSign", true),
        ef.create_extension("subjectKeyIdentifier", "hash", false)
      ]
      cert.add_extension ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")

      cert.sign(private_key, "SHA256")
    end
  end

  def subject
    @subject ||= "/C=US/ST=TX/L=Austin/O=Liant/OU=R&D/CN=localhost/emailAddress=admin@example.com"
  end

  def set_oauth_application(params = {})
    super({
      jwks: JSON.dump([public_jwk]),
      token_endpoint_auth_method: "tls_client_auth",
      tls_client_auth_subject_dn: subject
    }.merge(params))
  end

  def post_introspect(request_args = {})
    env "SSL_CLIENT_M_VERSION", certificate.version
    env "SSL_CLIENT_M_SERIAL", certificate.serial
    env "SSL_CLIENT_S_DN", subject
    env "SSL_CLIENT_S_DN_C", "US"
    env "SSL_CLIENT_S_DN_CN", "localhost"
    env "SSL_CLIENT_S_DN_Email", "admin@example.com"
    env "SSL_CLIENT_S_DN_L", "Austin"
    env "SSL_CLIENT_S_DN_O", "Liant"
    env "SSL_CLIENT_S_DN_OU", "R&D"
    env "SSL_CLIENT_S_DN_ST", "TX"
    env "SSL_CLIENT_S_DN_x509", "CN"
    env "SSL_CLIENT_SAN_DNS_1", "one.example.org"
    env "SSL_CLIENT_I_DN", subject
    env "SSL_CLIENT_I_DN_x509", "CN"
    env "SSL_CLIENT_V_START", certificate.not_before.httpdate
    env "SSL_CLIENT_V_END", certificate.not_after.httpdate
    env "SSL_CLIENT_V_REMAIN", (certificate.not_after - certificate.not_before) / 60 / 60 / 24
    env "SSL_CLIENT_A_SIG", certificate.signature_algorithm
    env "SSL_CLIENT_A_KEY", public_key.oid
    env "SSL_CLIENT_CERT", certificate.to_pem
    env "SSL_CLIENT_VERIFY", "SUCCESS"

    request_args = {
      client_id: request_args.delete(:client_id) || oauth_application[:client_id]
    }.merge(request_args).compact

    post("/introspect", request_args)
  end

  def oauth_feature
    %i[oauth_token_introspection oauth_tls_client_auth]
  end
end
