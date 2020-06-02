# frozen-string-literal: true

module Rodauth
  Feature.define(:oauth_jwt) do
    depends :oauth

    auth_value_method :oauth_jwt_token_issuer, "Example"
    auth_value_method :oauth_jwt_secret, nil
    auth_value_method :oauth_jwt_secret_path, nil
    auth_value_method :oauth_jwt_jwk_key_path, nil
    auth_value_method :oauth_jwt_encryption_method, "HS256"
    auth_value_method :oauth_jwt_audience, nil

    auth_value_methods :generate_jti

    private

    def generate_oauth_token(params = {}, should_generate_refresh_token = true)
      create_params = {
        oauth_grants_expires_in_column => Time.now + oauth_token_expires_in
      }.merge(params)

      if should_generate_refresh_token
        refresh_token = oauth_unique_id_generator

        if oauth_tokens_refresh_token_hash_column
          create_params[oauth_tokens_refresh_token_hash_column] = generate_token_hash(refresh_token)
        else
          create_params[oauth_tokens_refresh_token_column] = refresh_token
        end
      end

      oauth_token = _generate_oauth_token(create_params)

      issued_at = Time.current.utc.to_i

      secret = oauth_jwt_secret_path ? File.open(oauth_jwt_secret_path) : oauth_jwt_secret

      secret ||= oauth_application.secret

      secret = case oauth_jwt_encryption_method
               when /RS\d{3}/ # RSA
                 OpenSSL::PKey::RSA.new(secret)
               when /ES\d{3}/
                 OpenSSL::PKey::EC.new(secret)
               else
                 secret.respond_to?(:read) ? secret.read : secret
               end

      iat = Time.current.utc.to_i

      # Use the secret and iat to create a unique key per request to prevent replay attacks
      jti_raw = [secret, iat].join(":").to_s
      jti = Digest::MD5.hexdigest(jti_raw)

      payload = {
        sub: oauth_token[oauth_tokens_account_id_column],
        iss: oauth_jwt_token_issuer, # issuer
        iat: iat, # issued at

        # @see JWT reserved claims - https://tools.ietf.org/html/draft-jones-json-web-token-07#page-7
        jti: jti,
        exp: issued_at + oauth_token_expires_in,
        aud: oauth_jwt_audience,

        # one of the points of using jwt is avoiding database lookups, so we put here all relevant
        # token data.
        scopes: oauth_token[oauth_tokens_scopes_column]
      }

      headers = {}
      if oauth_jwt_jwk_key_path
        pubkey = OpenSSL::PKey::RSA.new(oauth_jwt_jwk_key_path)
        headers[:kid] = pubkey.kid
      end

      token = JWT.encode payload, secret, oauth_jwt_encryption_method, headers
      oauth_token[oauth_tokens_token_column] = token
      oauth_token
    end
  end
end
