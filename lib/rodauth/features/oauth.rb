# frozen-string-literal: true

module Rodauth
  Feature.define(:oauth, :Oauth) do
    depends :login
    error_flash "Please authorize to continue", "require_authorization"

    view :authorize, "Authorize"

    auth_value_method :grants_table, :oauth_grants
    auth_value_method :token_column, :token
    auth_value_method :authorize_path, "oauth/authorize"
    auth_value_method :default_scope, "profile.read"
    auth_value_method :authorization_required_error_status, 403
    session_key :flash_error_key, :error
    session_key :session_key, :account_id

    redirect(:require_authorization) do
      if logged_in?
        authorize_path
      else
        login_redirect
      end
    end

    def initialize(scope)
      @scope = scope
    end

    def authorization_token
      value = request["HTTP_AUTHORIZATION"].to_s

      scheme, token = value.split(" ", 2)

      authorization_required unless scheme == "Bearer"

      token
    end

    def oauth_authorize(scope = default_scope)
      grant = db[grants_table].filter(token_column => authorization_token).first

      # check if there is grant
      # check if grant was expired
      # check if grant has been revoked
      # check if permission for scoep exists
      if !grant ||
         Time.now.utc > (grant[:created_at] + expires_in.seconds) ||
         (grant[:revoked_at] && Time.now.utc > grant[:revoked_at]) ||
         !grants[:scopes].include?(scope)
        authorization_required
      end
    end

    def authorization_required
      set_redirect_error_status(authorization_required_error_status)
      set_redirect_error_flash(require_authorization_error_flash)
      redirect(require_authorization_redirect)
    end

    route(:oauth_authorize) do |r|
      require_account

      r.get do
        authorize_view
      end
    end
  end
end
