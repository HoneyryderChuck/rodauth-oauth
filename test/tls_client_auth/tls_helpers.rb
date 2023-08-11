# frozen_string_literal: true

require "openssl"
require "jwt"
require "time"

module RodauthOAuthTlsHelpers
  private

  def set_oauth_application(params = {})
    super({
      jwks: JSON.dump([public_jwk]),
      token_endpoint_auth_method: "tls_client_auth",
      tls_client_auth_subject_dn: subject
    }.merge(params))
  end

  def private_key
    @private_key ||= OpenSSL::PKey::RSA.generate(2048)
  end

  def public_key
    @public_key ||= private_key.public_key
  end

  def public_jwk
    @public_jwk ||= begin
      jwk = JWT::JWK.new(public_key).export.merge(use: "sig", alg: "RS256")
      jwk["x5c"] = [generate_thumbprint(public_key)]
      jwk
    end
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
        ef.create_extension("subjectKeyIdentifier", "hash", false),
        ef.create_extension("subjectAltName", "DNS:#{san_dns},IP:#{san_ip},URI:#{san_uri},email:#{san_email}", false)
      ]
      cert.add_extension ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")

      cert.sign(private_key, "SHA256")
    end
  end

  def subject
    "/C=US/ST=TX/L=Austin/O=Liant/OU=R&D/CN=localhost/emailAddress=admin@example.com"
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

  def set_ssl_meta_vars
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
    env "SSL_CLIENT_A_KEY", public_key.oid unless RUBY_ENGINE == "jruby"
    env "SSL_CLIENT_CERT", certificate.to_pem
    env "SSL_CLIENT_VERIFY", "SUCCESS"
  end
end
