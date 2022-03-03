# frozen_string_literal: true

module Rodauth
  Feature.define(:oauth_token_management, :OauthTokenManagement) do
    using RegexpExtensions

    depends :oauth_base

    view "oauth_tokens", "My Oauth Tokens", "oauth_tokens"

    button "Revoke", "oauth_token_revoke"

    auth_value_method :oauth_tokens_path, "oauth-tokens"

    %w[token refresh_token expires_in revoked_at].each do |param|
      translatable_method :"oauth_tokens_#{param}_label", param.gsub("_", " ").capitalize
    end

    auth_value_method :oauth_tokens_route, "oauth-tokens"
    auth_value_method :oauth_tokens_id_pattern, Integer

    auth_value_methods(
      :oauth_token_path
    )

    def oauth_tokens_path(opts = {})
      route_path(oauth_tokens_route, opts)
    end

    def oauth_tokens_url(opts = {})
      route_url(oauth_tokens_route, opts)
    end

    def oauth_token_path(id)
      "#{oauth_tokens_path}/#{id}"
    end

    def oauth_tokens
      request.on(oauth_tokens_route) do
        require_account

        request.get do
          scope.instance_variable_set(:@oauth_tokens, db[oauth_tokens_table]
            .select(Sequel[oauth_tokens_table].*, Sequel[oauth_applications_table][oauth_applications_name_column])
            .join(oauth_applications_table, Sequel[oauth_tokens_table][oauth_tokens_oauth_application_id_column] =>
              Sequel[oauth_applications_table][oauth_applications_id_column])
            .where(Sequel[oauth_tokens_table][oauth_tokens_account_id_column] => account_id)
                .where(oauth_tokens_revoked_at_column => nil))
          oauth_tokens_view
        end

        request.post(oauth_tokens_id_pattern) do |id|
          db[oauth_tokens_table]
            .where(oauth_tokens_id_column => id)
            .where(oauth_tokens_account_id_column => account_id)
            .update(oauth_tokens_revoked_at_column => Sequel::CURRENT_TIMESTAMP)

          set_notice_flash revoke_oauth_token_notice_flash
          redirect oauth_tokens_path || "/"
        end
      end
    end

    def check_csrf?
      case request.path
      when oauth_tokens_path
        only_json? ? false : super
      else
        super
      end
    end

    def check_valid_uri?(uri)
      URI::DEFAULT_PARSER.make_regexp(oauth_valid_uri_schemes).match?(uri)
    end
  end
end
