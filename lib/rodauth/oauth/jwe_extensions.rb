# frozen_string_literal: true

module JWE
  #
  # this is a monkey-patch!
  # it's necessary, as the original jwe does not support jwks.
  # if this works long term, it may be merged upstreamm.
  #
  def self.__rodauth_oauth_decrypt_from_jwks(payload, jwks, alg: "RSA-OAEP", enc: "A128GCM")
    header, enc_key, iv, ciphertext, tag = Serialization::Compact.decode(payload)
    header = JSON.parse(header)

    key = find_key_by_kid(jwks, header["kid"], alg, enc)

    check_params(header, key)

    cek = Alg.decrypt_cek(header["alg"], key, enc_key)
    cipher = Enc.for(header["enc"], cek, iv, tag)

    plaintext = cipher.decrypt(ciphertext, payload.split(".").first)

    apply_zip(header, plaintext, :decompress)
  end

  def self.__rodauth_oauth_encrypt_from_jwks(payload, jwks, alg: "RSA-OAEP", enc: "A128GCM", **more_headers)
    header = generate_header(alg, enc, more_headers)

    key = find_key_by_alg_enc(jwks, alg, enc)

    check_params(header, key)
    payload = apply_zip(header, payload, :compress)

    cipher = Enc.for(enc)
    cipher.cek = key if alg == "dir"

    json_hdr = header.to_json
    ciphertext = cipher.encrypt(payload, Base64.jwe_encode(json_hdr))

    generate_serialization(json_hdr, Alg.encrypt_cek(alg, key, cipher.cek), ciphertext, cipher)
  end

  def self.find_key_by_kid(jwks, kid, alg, enc)
    raise DecodeError, "No key id (kid) found from token headers" unless kid

    jwk = jwks.find { |key, _| (key[:kid] || key["kid"]) == kid }

    raise DecodeError, "Could not find public key for kid #{kid}" unless jwk
    raise DecodeError, "Expected a different encryption algorithm" unless alg == (jwk[:alg] || jwk["alg"])
    raise DecodeError, "Expected a different encryption method" unless enc == (jwk[:enc] || jwk["enc"])

    ::JWT::JWK.import(jwk).keypair
  end

  def self.find_key_by_alg_enc(jwks, alg, enc)
    jwk = jwks.find do |key, _|
      (key[:alg] || key["alg"]) == alg &&
        (key[:enc] || key["enc"]) == enc
    end

    raise DecodeError, "No key found" unless jwk

    ::JWT::JWK.import(jwk).keypair
  end
end
