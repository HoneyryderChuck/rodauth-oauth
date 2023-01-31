# frozen_string_literal: true

require "openssl"
require "ipaddr"
require "uri"
require "rodauth/oauth"

module Rodauth
  Feature.define(:oauth_tls_client_auth, :OauthTlsClientAuth) do
    depends :oauth_jwt_base

    auth_value_method :oauth_tls_client_certificate_bound_access_tokens, false

    %i[
      tls_client_auth_subject_dn tls_client_auth_san_dns
      tls_client_auth_san_uri tls_client_auth_san_ip
      tls_client_auth_san_email tls_client_certificate_bound_access_tokens
    ].each do |column|
      auth_value_method :"oauth_applications_#{column}_column", column
    end

    def oauth_token_endpoint_auth_methods_supported
      super | %w[tls_client_auth self_signed_tls_client_auth]
    end

    private

    def validate_token_params
      # For all requests to the authorization server utilizing mutual-TLS client authentication,
      # the client MUST include the client_id parameter
      redirect_response_error("invalid_request") if client_certificate && !param_or_nil("client_id")

      super
    end

    def require_oauth_application
      return super unless client_certificate

      authorization_required unless oauth_application

      if supports_auth_method?(oauth_application, "tls_client_auth")
        # It relies on a validated certificate chain [RFC5280]
        authorization_required unless request.env["SSL_CLIENT_VERIFY"] == "SUCCESS"

        # and a single subject distinguished name (DN) or a single subject alternative name (SAN) to
        # authenticate the client. Only one subject name value of any type is used for each client.

        name_matches = if oauth_application[:tls_client_auth_subject_dn]
                         distinguished_name_match?(client_certificate.subject, oauth_application[:tls_client_auth_subject_dn])
                       elsif (dns = oauth_application[:tls_client_auth_san_dns])
                         client_certificate_sans.any? { |san| san.tag == 2 && OpenSSL::SSL.verify_hostname(dns, san.value) }
                       elsif (uri = oauth_application[:tls_client_auth_san_uri])
                         uri = URI(uri)
                         client_certificate_sans.any? { |san| san.tag == 6 && URI(san.value) == uri }
                       elsif (ip = oauth_application[:tls_client_auth_san_ip])
                         ip = IPAddr.new(ip).hton
                         client_certificate_sans.any? { |san| san.tag == 7 && san.value == ip }
                       elsif (email = oauth_application[:tls_client_auth_san_email])
                         client_certificate_sans.any? { |san| san.tag == 1 && san.value == email }
                       else
                         false
                       end
        authorization_required unless name_matches

        oauth_application
      elsif supports_auth_method?(oauth_application, "self_signed_tls_client_auth")
        jwks = oauth_application_jwks(oauth_application)

        thumbprint = jwk_thumbprint(key_to_jwk(client_certificate.public_key))

        # The client is successfully authenticated if the certificate that it presented during the handshake
        # matches one of the certificates configured or registered for that particular client.
        authorization_required unless jwks.any? { |jwk| Array(jwk[:x5c]).first == thumbprint }

        oauth_application
      else
        super
      end
    rescue URI::InvalidURIError, IPAddr::InvalidAddressError
      authorization_required
    end

    def jwt_claims(*)
      claims = super

      return claims unless client_certificate && (
        oauth_tls_client_certificate_bound_access_tokens ||
        oauth_application[oauth_applications_tls_client_certificate_bound_access_tokens_column]
      )

      jwk = jwk_import(client_certificate.public_key)

      claims[:cnf] = {
        "x5t#S256" => jwk_thumbprint(jwk)
      }

      claims
    end

    def json_token_introspect_payload(grant_or_claims)
      claims = super

      return claims unless grant_or_claims && grant_or_claims[oauth_grants_certificate_thumbprint_column]

      claims[:cnf] = {
        "x5t#S256" => grant_or_claims[oauth_grants_certificate_thumbprint_column]
      }

      claims
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:tls_client_certificate_bound_access_tokens] = oauth_tls_client_certificate_bound_access_tokens
      end
    end

    def client_certificate
      return @client_certificate if defined?(@client_certificate)

      return unless request.env["SSL_CLIENT_CERT"]

      @certificate = OpenSSL::X509::Certificate.new(request.env["SSL_CLIENT_CERT"])
    end

    def client_certificate_sans
      return @client_certificate_sans if defined?(@client_certificate_sans)

      @client_certificate_sans = begin
        return [] unless client_certificate

        san = client_certificate.extensions.find { |ext| ext.oid == "subjectAltName" }

        return [] unless san

        ostr = OpenSSL::ASN1.decode(san.to_der).value.last

        sans = OpenSSL::ASN1.decode(ostr.value)

        return [] unless sans

        sans.value
      end
    end

    def distinguished_name_match?(sub1, sub2)
      sub1 = OpenSSL::X509::Name.parse(sub1) if sub1.is_a?(String)
      sub2 = OpenSSL::X509::Name.parse(sub2) if sub2.is_a?(String)
      # OpenSSL::X509::Name#cp calls X509_NAME_cmp via openssl.
      # https://www.openssl.org/docs/manmaster/man3/X509_NAME_cmp.html
      # This procedure adheres to the matching rules for Distinguished Names (DN) given in
      # RFC 4517 section 4.2.15 and RFC 5280 section 7.1.
      sub1.cmp(sub2).zero?
    end
  end
end
