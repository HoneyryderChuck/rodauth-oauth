# frozen_string_literal: true

require "rodauth/oauth/version"
require "rodauth/oauth/http_extensions"

module Rodauth
  Feature.define(:oauth_jwt_jwks, :OauthJwtJwks) do
    depends :oauth_jwt_base

    auth_value_methods(:jwks_set)

    route(:jwks) do |r|
      next unless is_authorization_server?

      r.get do
        json_response_success({ keys: jwks_set }, true)
      end
    end

    private

    def oauth_server_metadata_body(path = nil)
      metadata = super
      metadata.merge!(jwks_uri: jwks_url)
      metadata
    end

    def jwks_set
      @jwks_set ||= [
        *(
          unless oauth_jwt_public_keys.empty?
            oauth_jwt_public_keys.flat_map { |algo, pkeys| Array(pkeys).map { |pkey| jwk_export(pkey).merge(use: "sig", alg: algo) } }
          end
        ),
        *(
          unless oauth_jwt_jwe_public_keys.empty?
            oauth_jwt_jwe_public_keys.flat_map do |(algo, _enc), pkeys|
              Array(pkeys).map do |pkey|
                jwk_export(pkey).merge(use: "enc", alg: algo)
              end
            end
          end
        )
      ].compact
    end
  end
end
