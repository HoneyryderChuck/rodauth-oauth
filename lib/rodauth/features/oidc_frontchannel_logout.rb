# frozen_string_literal: true

require "rodauth/oauth"

module Rodauth
  Feature.define(:oidc_frontchannel_logout, :OidFrontchannelLogout) do
    depends :logout, :oidc

    view "frontchannel_logout", "Logout", "frontchannel_logout"

    session_key :visited_sites_key, :visited_sites
    translatable_method :oauth_frontchannel_logout_redirecting_lead, "You are being redirected..."
    translatable_method :oauth_frontchannel_logout_redirecting_label, "please click %<link>s if your browser does not " \
                                                                      "redirect you in a few seconds."
    translatable_method :oauth_frontchannel_logout_redirecting_link_label, "here"
    auth_value_method :frontchannel_logout_session_supported, true
    auth_value_method :oauth_applications_frontchannel_logout_uri_column, :frontchannel_logout_uri
    auth_value_method :oauth_applications_frontchannel_logout_session_required_column, :frontchannel_logout_session_required

    attr_reader :frontchannel_logout_urls

    def logout
      @visited_sites = session[visited_sites_key]

      super
    end

    def logout_response
      visited_sites = @visited_sites

      return super unless visited_sites

      logout_urls = db[oauth_applications_table]
                    .where(oauth_applications_client_id_column => visited_sites.map(&:first))
                    .as_hash(oauth_applications_client_id_column, oauth_applications_frontchannel_logout_uri_column)

      @frontchannel_logout_urls = logout_urls.flat_map do |client_id, logout_url|
        next unless logout_url

        sids = visited_sites.select { |cid, _| cid == client_id }.map(&:last)

        sids.map do |sid|
          logout_url = URI(logout_url)

          if sid
            query = logout_url.query
            query = if query
                      URI.decode_www_form(query)
                    else
                      []
                    end
            query << ["iss", oauth_jwt_issuer]
            query << ["sid", sid]
            logout_url.query = URI.encode_www_form(query)
          end

          logout_url
        end
      end.compact

      return super if logout_urls.empty?

      set_notice_flash logout_notice_flash
      frontchannel_logout_view
    end

    private

    def id_token_claims(oauth_grant, signing_algorithm)
      claims = super

      return claims unless oauth_application[oauth_applications_frontchannel_logout_uri_column]

      visited_sites = session[visited_sites_key] || []

      sid = compute_hmac(session_value.to_s) if requires_frontchannel_logout_session?(oauth_application)

      claims[:sid] = sid if sid

      visited_site = [oauth_application[oauth_applications_client_id_column], sid]

      unless visited_sites.include?(visited_site)
        visited_sites << visited_site
        set_session_value(visited_sites_key, visited_sites)
      end

      claims
    end

    def requires_frontchannel_logout_session?(oauth_application)
      (
        oauth_application &&
        oauth_application[oauth_applications_frontchannel_logout_session_required_column]
      ) || frontchannel_logout_session_supported
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:frontchannel_logout_supported] = true
        data[:frontchannel_logout_session_supported] = frontchannel_logout_session_supported
      end
    end
  end
end
