# frozen_string_literal: true

require "openssl"
require "test_helper"
require_relative "./token_authorization_code"

class RodauthOAuthTokenAuthorizationCodeTlsClientAuthTest < RodaIntegration
  include RodauthOAuthTokenAuthorizationCodeTest

  def test_token_authorization_code_no_params
    setup_application

    post("/token")
    verify_response(401)
    assert json_body["error"] == "invalid_client"
  end

  def test_token_authorization_code_no_client_secret
    setup_application

    post("/token",
         client_id: oauth_application[:client_id],
         grant_type: "authorization_code",
         code: oauth_grant[:code],
         redirect_uri: oauth_grant[:redirect_uri])

    verify_response(401)
    assert json_body["error"] == "invalid_client"
  end

  def test_token_authorization_code_self_signed
    setup_application

    oauth_application = set_oauth_application(
      token_endpoint_auth_method: "self_signed_tls_client_auth"
    )
    oauth_grant = set_oauth_grant(oauth_application: oauth_application)

    post_token(client_id: oauth_application[:client_id],
               grant_type: "authorization_code",
               code: oauth_grant[:code],
               redirect_uri: oauth_grant[:redirect_uri])

    verify_response(200)

    assert db[:oauth_grants].count == 1
    oauth_grant = db[:oauth_grants].first
    verify_access_token_response(json_body, oauth_grant)
  end

  def test_token_authorization_code_san_dns
    setup_application

    oauth_application = set_oauth_application(
      tls_client_auth_subject_dn: nil,
      tls_client_auth_san_dns: san_dns
    )
    oauth_grant = set_oauth_grant(oauth_application: oauth_application)

    post_token(client_id: oauth_application[:client_id],
               grant_type: "authorization_code",
               code: oauth_grant[:code],
               redirect_uri: oauth_grant[:redirect_uri])

    verify_response(200)

    assert db[:oauth_grants].count == 1
    oauth_grant = db[:oauth_grants].first
    verify_access_token_response(json_body, oauth_grant)
  end

  def test_token_authorization_code_san_uri
    setup_application

    oauth_application = set_oauth_application(
      tls_client_auth_subject_dn: nil,
      tls_client_auth_san_uri: san_uri
    )
    oauth_grant = set_oauth_grant(oauth_application: oauth_application)

    post_token(client_id: oauth_application[:client_id],
               grant_type: "authorization_code",
               code: oauth_grant[:code],
               redirect_uri: oauth_grant[:redirect_uri])

    verify_response(200)

    assert db[:oauth_grants].count == 1
    oauth_grant = db[:oauth_grants].first
    verify_access_token_response(json_body, oauth_grant)
  end

  def test_token_authorization_code_san_ip
    setup_application

    oauth_application = set_oauth_application(
      tls_client_auth_subject_dn: nil,
      tls_client_auth_san_ip: san_ip
    )
    oauth_grant = set_oauth_grant(oauth_application: oauth_application)

    post_token(client_id: oauth_application[:client_id],
               grant_type: "authorization_code",
               code: oauth_grant[:code],
               redirect_uri: oauth_grant[:redirect_uri])

    verify_response(200)

    assert db[:oauth_grants].count == 1
    oauth_grant = db[:oauth_grants].first
    verify_access_token_response(json_body, oauth_grant)
  end

  def test_token_authorization_code_san_email
    setup_application

    oauth_application = set_oauth_application(
      tls_client_auth_subject_dn: nil,
      tls_client_auth_san_email: san_email
    )
    oauth_grant = set_oauth_grant(oauth_application: oauth_application)

    post_token(client_id: oauth_application[:client_id],
               grant_type: "authorization_code",
               code: oauth_grant[:code],
               redirect_uri: oauth_grant[:redirect_uri])

    verify_response(200)

    assert db[:oauth_grants].count == 1
    oauth_grant = db[:oauth_grants].first
    verify_access_token_response(json_body, oauth_grant)
  end

  def test_token_authorization_code_successful
    setup_application

    post_token(client_id: oauth_application[:client_id],
               grant_type: "authorization_code",
               code: oauth_grant[:code],
               redirect_uri: oauth_grant[:redirect_uri])

    verify_response(200)

    assert db[:oauth_grants].count == 1

    oauth_grant = db[:oauth_grants].first

    verify_access_token_response(json_body, oauth_grant)
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
        ef.create_extension("subjectKeyIdentifier", "hash", false),
        ef.create_extension("subjectAltName", "DNS:#{san_dns},IP:#{san_ip},URI:#{san_uri},email:#{san_email}", false)
      ]
      cert.add_extension ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")

      cert.sign(private_key, "SHA256")
    end
  end

  def subject
    @subject ||= "/C=US/ST=TX/L=Austin/O=Liant/OU=R&D/CN=localhost/emailAddress=admin@example.com"
  end

  def san_dns
    "one.example.org"
  end

  def san_ip
    "127.0.0.1"
  end

  def san_uri
    "ldap://somehost.com"
  end

  def san_email
    "admin@example.com"
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
    env "SSL_CLIENT_VERIFY", "NONE"

    request_args = {
      client_id: request_args.delete(:client_id) || oauth_application[:client_id]
    }.merge(request_args).compact

    post("/token", request_args)
  end

  def oauth_feature
    %i[oauth_authorization_code_grant oauth_tls_client_auth]
  end
end
