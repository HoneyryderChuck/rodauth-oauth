# frozen_string_literal: true

module Rodauth
  Feature.define(:oauth_grant_management, :OauthTokenManagement) do
    depends :oauth_management_base, :oauth_token_revocation

    view "oauth_grants", "My Oauth Gramts", "oauth_grants"

    button "Revoke", "oauth_grant_revoke"

    auth_value_method :oauth_grants_path, "oauth-grants"

    %w[token refresh_token expires_in revoked_at].each do |param|
      translatable_method :"oauth_grants_#{param}_label", param.gsub("_", " ").capitalize
    end

    auth_value_method :oauth_grants_route, "oauth-grants"
    auth_value_method :oauth_grants_id_pattern, Integer
    auth_value_method :oauth_grants_per_page, 20

    auth_value_methods(
      :oauth_grant_path
    )

    def oauth_grants_path(opts = {})
      route_path(oauth_grants_route, opts)
    end

    def oauth_grants_url(opts = {})
      route_url(oauth_grants_route, opts)
    end

    def oauth_grant_path(id)
      "#{oauth_grants_path}/#{id}"
    end

    def load_oauth_grant_management_routes
      request.on(oauth_grants_route) do
        require_account

        request.post(oauth_grants_id_pattern) do |id|
          db[oauth_grants_table]
            .where(oauth_grants_id_column => id)
            .where(oauth_grants_account_id_column => account_id)
            .update(oauth_grants_revoked_at_column => Sequel::CURRENT_TIMESTAMP)

          set_notice_flash revoke_oauth_grant_notice_flash
          redirect oauth_grants_path || "/"
        end

        request.is do
          request.get do
            page = Integer(param_or_nil("page") || 1)
            per_page = per_page_param(oauth_grants_per_page)

            scope.instance_variable_set(:@oauth_grants, db[oauth_grants_table]
              .select(Sequel[oauth_grants_table].*, Sequel[oauth_applications_table][oauth_applications_name_column])
              .join(oauth_applications_table, Sequel[oauth_grants_table][oauth_grants_oauth_application_id_column] =>
                Sequel[oauth_applications_table][oauth_applications_id_column])
              .where(Sequel[oauth_grants_table][oauth_grants_account_id_column] => account_id)
              .where(oauth_grants_revoked_at_column => nil)
              .order(Sequel.desc(oauth_grants_id_column))
              .paginate(page, per_page))
            oauth_grants_view
          end
        end
      end
    end

    def check_csrf?
      case request.path
      when oauth_grants_path
        only_json? ? false : super
      else
        super
      end
    end
  end
end
