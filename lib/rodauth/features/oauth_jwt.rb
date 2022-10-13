# frozen_string_literal: true

require "rodauth/oauth"
require "rodauth/oauth/http_extensions"

module Rodauth
  Feature.define(:oauth_jwt, :OauthJwt) do
    depends :oauth_jwt_base, :oauth_jwt_jwks

    auth_value_method :oauth_jwt_access_tokens, true

    def require_oauth_authorization(*scopes)
      return super unless oauth_jwt_access_tokens

      authorization_required unless authorization_token

      token_scopes = authorization_token["scope"].split(" ")

      authorization_required unless scopes.any? { |scope| token_scopes.include?(scope) }
    end

    def oauth_token_subject
      return super unless oauth_jwt_access_tokens

      return unless authorization_token

      authorization_token["sub"]
    end

    def current_oauth_account
      subject = oauth_token_subject

      return if subject == authorization_token["client_id"]

      oauth_account_ds(subject).first
    end

    def current_oauth_application
      db[oauth_applications_table].where(
        oauth_applications_client_id_column => authorization_token["client_id"]
      ).first
    end

    private

    def authorization_token
      return super unless oauth_jwt_access_tokens

      return @authorization_token if defined?(@authorization_token)

      @authorization_token = begin
        bearer_token = fetch_access_token

        return unless bearer_token

        jwt_claims = jwt_decode(bearer_token)

        return unless jwt_claims

        return unless jwt_claims["sub"]

        return unless jwt_claims["aud"]

        jwt_claims
      end
    end

    # /token

    def create_token_from_token(_grant, update_params)
      oauth_grant = super

      if oauth_jwt_access_tokens
        access_token = _generate_jwt_access_token(oauth_grant)
        oauth_grant[oauth_grants_token_column] = access_token
      end
      oauth_grant
    end

    def generate_token(_grant_params = {}, should_generate_refresh_token = true)
      oauth_grant = super
      if oauth_jwt_access_tokens
        access_token = _generate_jwt_access_token(oauth_grant)
        oauth_grant[oauth_grants_token_column] = access_token
      end
      oauth_grant
    end

    def _generate_jwt_access_token(oauth_grant)
      claims = jwt_claims(oauth_grant)

      # one of the points of using jwt is avoiding database lookups, so we put here all relevant
      # token data.
      claims[:scope] = oauth_grant[oauth_grants_scopes_column]

      jwt_encode(claims)
    end

    def _generate_access_token(*)
      return super unless oauth_jwt_access_tokens
    end

    def jwt_claims(oauth_grant)
      issued_at = Time.now.to_i

      {
        iss: oauth_jwt_issuer, # issuer
        iat: issued_at, # issued at
        #
        # sub  REQUIRED - as defined in section 4.1.2 of [RFC7519].  In case of
        # access tokens obtained through grants where a resource owner is
        # involved, such as the authorization code grant, the value of "sub"
        # SHOULD correspond to the subject identifier of the resource owner.
        # In case of access tokens obtained through grants where no resource
        # owner is involved, such as the client credentials grant, the value
        # of "sub" SHOULD correspond to an identifier the authorization
        # server uses to indicate the client application.
        sub: jwt_subject(oauth_grant),
        client_id: oauth_application[oauth_applications_client_id_column],

        exp: issued_at + oauth_access_token_expires_in,
        aud: oauth_jwt_audience
      }
    end
  end
end
