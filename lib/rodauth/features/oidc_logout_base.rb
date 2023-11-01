# frozen_string_literal: true

require "rodauth/oauth"

module Rodauth
  Feature.define(:oidc_logout_base, :OidcLogoutBase) do
    depends :oidc

    session_key :visited_sites_key, :visited_sites

    private

    # set application/sid in visited sites when required
    def create_oauth_grant(create_params = {})
      sid_in_visited_sites

      super
    end

    def active_sessions?(session_id)
      !active_sessions_ds.where(active_sessions_session_id_column => session_id).empty?
    end

    def session_id_in_claims(oauth_grant, claims)
      oauth_application_in_visited_sites do
        if should_set_sid_in_visited_sites?(oauth_application)
          # id_token or token response types
          session_id = if (sess = session[session_id_session_key])
                         compute_hmac(sess)
                       else
                         # code response type
                         ds = db[active_sessions_table]
                         ds = ds.where(active_sessions_account_id_column => oauth_grant[oauth_grants_account_id_column])
                         ds = ds.order(Sequel.desc(active_sessions_last_use_column))
                         ds.get(active_sessions_session_id_column)
                       end

          claims[:sid] = session_id
        end
      end
    end

    def oauth_application_in_visited_sites
      visited_sites = session[visited_sites_key] || []

      session_id = yield

      visited_site = [oauth_application[oauth_applications_client_id_column], session_id]

      return if visited_sites.include?(visited_site)

      visited_sites << visited_site
      set_session_value(visited_sites_key, visited_sites)
    end

    def sid_in_visited_sites
      return unless should_set_oauth_application_in_visited_sites?

      oauth_application_in_visited_sites do
        if should_set_sid_in_visited_sites?(oauth_application)
          ds = active_sessions_ds.order(Sequel.desc(active_sessions_last_use_column))

          ds.get(active_sessions_session_id_column)
        end
      end
    end

    def should_set_oauth_application_in_visited_sites?
      false
    end

    def should_set_sid_in_visited_sites?(*)
      false
    end
  end
end
