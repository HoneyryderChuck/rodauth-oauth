# frozen_string_literal: true

class SelfSignedCert
  attr_reader :private_key, :cert

  def initialize(name, root_key: nil, root_cert: nil)
    @private_key = if File.exist?(key_path(name))
                     OpenSSL::PKey::RSA.new(File.read(key_path(name)))
                   else
                     key = OpenSSL::PKey::RSA.generate(2048)
                     File.write(key_path(name), key.to_pem)
                     key
                   end

    @cert = if File.exist?(cert_path(name))
              OpenSSL::X509::Certificate.new(File.read(cert_path(name)))
            else
              public_key = @private_key.public_key
              cert = OpenSSL::X509::Certificate.new
              name = OpenSSL::X509::Name.parse("/CN=#{name}")
              cert.subject = name
              cert.issuer = root_cert ? root_cert.subject : name
              cert.not_before = Time.now
              cert.not_after = Time.now + (365 * 24 * 60 * 60)
              cert.public_key = public_key
              cert.serial = root_cert ? 2 : 1
              cert.version = 2
              ef = OpenSSL::X509::ExtensionFactory.new
              ef.subject_certificate = cert
              ef.issuer_certificate = root_cert || cert
              if root_cert
                cert.extensions = [
                  ef.create_extension("basicConstraints", "CA:FALSE", true),
                  ef.create_extension("keyUsage", "digitalSignature", true),
                  ef.create_extension("subjectKeyIdentifier", "hash", false),
                  ef.create_extension("subjectAltName", "DNS:localhost,IP:127.0.0.1", false)
                ]
              else
                # CA
                cert.extensions = [
                  ef.create_extension("basicConstraints", "CA:TRUE", true),
                  ef.create_extension("keyUsage", "keyCertSign, cRLSign", true),
                  ef.create_extension("subjectKeyIdentifier", "hash", false)
                ]
                cert.add_extension ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")
              end

              cert.sign(root_key || @private_key, "SHA256")
              File.write(cert_path(name), cert.to_pem)
              cert
            end
  end

  private

  def key_path(name)
    File.join(__dir__, "#{name}-key.pem")
  end

  def cert_path(name)
    File.join(__dir__, "#{name}-cert.pem")
  end
end
