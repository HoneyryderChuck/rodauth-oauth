# frozen_string_literal: true

require "rodauth/oauth"

module Rodauth
  Feature.define(:oidc_backchannel_logout, :OidBackchannelLogout) do
    depends :logout, :oidc

    session_key :visited_sites_key, :visited_sites
    auth_value_method :oauth_logout_token_expires_in, 60 # 1 minute
    auth_value_method :backchannel_logout_session_supported, true
    auth_value_method :oauth_applications_backchannel_logout_uri_column, :backchannel_logout_uri
    auth_value_method :oauth_applications_backchannel_logout_session_required_column, :backchannel_logout_session_required

    auth_methods(
      :perform_logout_requests
    )

    def logout
      visited_sites = session[visited_sites_key]

      return super unless visited_sites

      oauth_applications = db[oauth_applications_table].where(oauth_applications_client_id_column => visited_sites.map(&:first))
                                                       .as_hash(oauth_applications_id_column)

      logout_params = oauth_applications.flat_map do |_id, oauth_application|
        logout_url = oauth_application[oauth_applications_backchannel_logout_uri_column]

        next unless logout_url

        client_id = oauth_application[oauth_applications_client_id_column]

        sids = visited_sites.select { |cid, _| cid == client_id }.map(&:last)

        sids.map do |sid|
          logout_token = generate_logout_token(oauth_application, sid)

          [logout_url, logout_token]
        end
      end.compact

      perform_logout_requests(logout_params) unless logout_params.empty?

      # now we can clear the session
      super
    end

    private

    def generate_logout_token(oauth_application, sid)
      issued_at = Time.now.to_i

      logout_claims = {
        iss: oauth_jwt_issuer, # issuer
        iat: issued_at, # issued at
        exp: issued_at + oauth_logout_token_expires_in,
        aud: oauth_application[oauth_applications_client_id_column],
        events: "http://schemas.openid.net/event/backchannel-logout"
      }

      logout_claims[:sid] = sid if sid

      signing_algorithm = oauth_application[oauth_applications_id_token_signed_response_alg_column] ||
                          oauth_jwt_keys.keys.first

      params = {
        jwks: oauth_application_jwks(oauth_application),
        headers: { typ: "logout+jwt" },
        signing_algorithm: signing_algorithm,
        encryption_algorithm: oauth_application[oauth_applications_id_token_encrypted_response_alg_column],
        encryption_method: oauth_application[oauth_applications_id_token_encrypted_response_enc_column]
      }.compact

      jwt_encode(logout_claims, **params)
    end

    def perform_logout_requests(logout_params)
      # performs logout requests sequentially
      logout_params.each do |logout_url, logout_token|
        http_request(logout_url, { "logout_token" => logout_token })
      rescue StandardError
        warn "failed to perform backchannel logout on #{logout_url}"
      end
    end

    def id_token_claims(oauth_grant, signing_algorithm)
      claims = super

      return claims unless oauth_application[oauth_applications_backchannel_logout_uri_column]

      visited_sites = session[visited_sites_key] || []

      sid = compute_hmac(compute_hmac(request.env["HTTP_COOKIE"])) if requires_backchannel_logout_session?(oauth_application)

      claims[:sid] = sid if sid

      visited_site = [oauth_application[oauth_applications_client_id_column], sid]

      unless visited_sites.include?(visited_site)
        visited_sites << visited_site
        set_session_value(visited_sites_key, visited_sites)
      end

      claims
    end

    def requires_backchannel_logout_session?(oauth_application)
      (
        oauth_application &&
        oauth_application[oauth_applications_backchannel_logout_session_required_column]
      ) || backchannel_logout_session_supported
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:backchannel_logout_supported] = true
        data[:backchannel_logout_session_supported] = backchannel_logout_session_supported
      end
    end
  end
end
