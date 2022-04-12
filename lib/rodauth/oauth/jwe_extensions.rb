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

  def self.find_key_by_kid(jwks, kid, alg, enc)
    raise DecodeError, "No key id (kid) found from token headers" unless kid

    jwk = jwks.find { |key, _| (key[:kid] || key["kid"]) == kid }

    raise DecodeError, "Could not find public key for kid #{kid}" unless jwk
    raise DecodeError, "Expected a different encryption algorithm" unless alg == (jwk[:alg] || jwk["alg"])
    raise DecodeError, "Expected a different encryption method" unless enc == (jwk[:enc] || jwk["enc"])

    ::JWT::JWK.import(jwk).keypair
  end
end
