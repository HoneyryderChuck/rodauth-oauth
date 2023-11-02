# frozen_string_literal: true

require "rodauth/oauth"

# :nocov:
raise LoadError, "the `:oidc_frontchannel_logout` requires rodauth 2.32.0 or higher" if Rodauth::VERSION < "2.32.0"

# :nocov:

module Rodauth
  Feature.define(:oidc_frontchannel_logout, :OidFrontchannelLogout) do
    depends :logout, :oidc_logout_base

    view "frontchannel_logout", "Logout", "frontchannel_logout"

    translatable_method :oauth_frontchannel_logout_redirecting_lead, "You are being redirected..."
    translatable_method :oauth_frontchannel_logout_redirecting_label, "please click %<link>s if your browser does not " \
                                                                      "redirect you in a few seconds."
    translatable_method :oauth_frontchannel_logout_redirecting_link_label, "here"
    auth_value_method :frontchannel_logout_session_supported, true
    auth_value_method :frontchannel_logout_redirect_timeout, 5
    auth_value_method :oauth_applications_frontchannel_logout_uri_column, :frontchannel_logout_uri
    auth_value_method :oauth_applications_frontchannel_logout_session_required_column, :frontchannel_logout_session_required

    attr_reader :frontchannel_logout_urls

    attr_reader :frontchannel_logout_redirect

    def logout
      @visited_sites = session[visited_sites_key]

      super
    end

    def _logout_response
      visited_sites = @visited_sites

      return super unless visited_sites

      logout_urls = db[oauth_applications_table]
                    .where(oauth_applications_client_id_column => visited_sites.map(&:first))
                    .as_hash(oauth_applications_client_id_column, oauth_applications_frontchannel_logout_uri_column)

      return super if logout_urls.empty?

      generate_frontchannel_logout_urls(visited_sites, logout_urls)

      @frontchannel_logout_redirect = logout_redirect

      set_notice_flash logout_notice_flash
      return_response frontchannel_logout_view
    end

    # overrides rp-initiate logout response
    def _oidc_logout_response
      visited_sites = @visited_sites

      return super unless visited_sites

      logout_urls = db[oauth_applications_table]
                    .where(oauth_applications_client_id_column => visited_sites.map(&:first))
                    .as_hash(oauth_applications_client_id_column, oauth_applications_frontchannel_logout_uri_column)

      return super if logout_urls.empty?

      generate_frontchannel_logout_urls(visited_sites, logout_urls)

      @frontchannel_logout_redirect = oidc_logout_redirect

      set_notice_flash logout_notice_flash
      return_response frontchannel_logout_view
    end

    private

    def generate_frontchannel_logout_urls(visited_sites, logout_urls)
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
    end

    def id_token_claims(oauth_grant, signing_algorithm)
      claims = super

      return claims unless oauth_application[oauth_applications_frontchannel_logout_uri_column]

      session_id_in_claims(oauth_grant, claims)

      claims
    end

    def should_set_oauth_application_in_visited_sites?
      true
    end

    def should_set_sid_in_visited_sites?(oauth_application)
      super || requires_frontchannel_logout_session?(oauth_application)
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
