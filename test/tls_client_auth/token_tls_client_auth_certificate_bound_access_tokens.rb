# frozen_string_literal: true

require "test_helper"

class RodauthOauthJWTTokenTlsClientAuuthCertificateBoundTest < JWTIntegration
  include Rack::Test::Methods

  def test_oauth_jwt_authorization_code_not_certificate_bound
    setup_application

    post_token(
      client_id: oauth_application[:client_id],
      grant_type: "authorization_code",
      code: oauth_grant[:code],
      redirect_uri: oauth_grant[:redirect_uri]
    )

    verify_response

    oauth_grant = verify_oauth_grant

    verify_access_token_response(json_body, oauth_grant, @rsa_public, "RS256")
    assert !json_body.key?("cnf")
  end

  def test_oauth_jwt_authorization_code_config_certificate_bound
    rodauth do
      oauth_tls_client_certificate_bound_access_tokens true
    end
    setup_application

    post_token(client_id: oauth_application[:client_id],
               grant_type: "authorization_code",
               code: oauth_grant[:code],
               redirect_uri: oauth_grant[:redirect_uri])

    verify_response

    oauth_grant = verify_oauth_grant

    claims = verify_access_token_response(json_body, oauth_grant, @rsa_public, "RS256")
    assert claims.key?("cnf")
    assert claims["cnf"].key?("x5t#S256")
    assert claims["cnf"]["x5t#S256"] == oauth_grant[:certificate_thumbprint]
  end

  def test_oauth_jwt_authorization_code_application_certificate_bound
    rodauth do
      oauth_tls_client_certificate_bound_access_tokens false
    end
    setup_application
    oauth_application = set_oauth_application(
      tls_client_certificate_bound_access_tokens: true
    )
    oauth_grant = set_oauth_grant(
      oauth_application: oauth_application
    )

    post_token(client_id: oauth_application[:client_id],
               grant_type: "authorization_code",
               code: oauth_grant[:code],
               redirect_uri: oauth_grant[:redirect_uri])

    verify_response

    oauth_grant = verify_oauth_grant

    claims = verify_access_token_response(json_body, oauth_grant, @rsa_public, "RS256")
    assert claims.key?("cnf")
    assert claims["cnf"].key?("x5t#S256")
    assert claims["cnf"]["x5t#S256"] == oauth_grant[:certificate_thumbprint]
  end

  private

  def setup_application(*)
    rsa_private = OpenSSL::PKey::RSA.generate 2048
    @rsa_public = rsa_private.public_key
    rodauth do
      oauth_jwt_keys("RS256" => rsa_private)
      oauth_jwt_public_keys("RS256" => @rsa_public)
    end
    super
  end

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

  def post_token(request_args)
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

    post("/token", request_args)
  end

  def oauth_feature
    %i[oauth_authorization_code_grant oauth_jwt oauth_tls_client_auth]
  end
end
