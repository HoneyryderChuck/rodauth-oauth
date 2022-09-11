# frozen_string_literal: true

require "time"
require "base64"
require "securerandom"
require "rodauth/version"
require "rodauth/oauth/version"
require "rodauth/oauth/database_extensions"
require "rodauth/oauth/refinements"
require "rodauth/oauth/http_extensions"

module Rodauth
  Feature.define(:oauth_base, :OauthBase) do
    using RegexpExtensions
    include OAuth::HTTPExtensions

    auth_value_methods(:http_request)
    auth_value_methods(:http_request_cache)

    SCOPES = %w[profile.read].freeze

    before "token"

    error_flash "Please authorize to continue", "require_authorization"
    error_flash "You are not authorized to revoke this token", "revoke_unauthorized_account"

    button "Cancel", "oauth_cancel"

    auth_value_method :json_response_content_type, "application/json"

    auth_value_method :oauth_grant_expires_in, 60 * 5 # 5 minutes
    auth_value_method :oauth_token_expires_in, 60 * 60 # 60 minutes
    auth_value_method :oauth_refresh_token_expires_in, 60 * 60 * 24 * 360 # 1 year
    auth_value_method :oauth_unique_id_generation_retries, 3

    auth_value_method :oauth_response_mode, "query"
    auth_value_method :oauth_auth_methods_supported, %w[client_secret_basic client_secret_post]

    auth_value_method :oauth_valid_uri_schemes, %w[https]
    auth_value_method :oauth_scope_separator, " "

    # OAuth Grants
    auth_value_method :oauth_grants_table, :oauth_grants
    auth_value_method :oauth_grants_id_column, :id
    %i[
      account_id oauth_application_id
      redirect_uri code scopes access_type
      expires_in revoked_at
      token refresh_token
    ].each do |column|
      auth_value_method :"oauth_grants_#{column}_column", column
    end

    # Oauth Token Hash
    auth_value_method :oauth_grants_token_hash_column, nil
    auth_value_method :oauth_grants_refresh_token_hash_column, nil

    # Access Token reuse
    auth_value_method :oauth_reuse_access_token, false

    auth_value_method :oauth_applications_table, :oauth_applications
    auth_value_method :oauth_applications_id_column, :id

    %i[
      account_id
      name description scopes
      client_id client_secret
      homepage_url redirect_uri
      token_endpoint_auth_method grant_types response_types
      logo_uri tos_uri policy_uri jwks jwks_uri
      contacts software_id software_version
    ].each do |column|
      auth_value_method :"oauth_applications_#{column}_column", column
    end

    auth_value_method :oauth_authorization_required_error_status, 401
    auth_value_method :oauth_invalid_response_status, 400
    auth_value_method :oauth_already_in_use_response_status, 409

    # Feature options
    auth_value_method :oauth_application_scopes, SCOPES
    auth_value_method :oauth_token_type, "bearer"
    auth_value_method :oauth_refresh_token_protection_policy, "none" # can be: none, sender_constrained, rotation

    translatable_method :oauth_invalid_client_message, "Invalid client"
    translatable_method :oauth_invalid_grant_type_message, "Invalid grant type"
    translatable_method :oauth_invalid_grant_message, "Invalid grant"
    translatable_method :oauth_invalid_scope_message, "Invalid scope"
    translatable_method :oauth_unsupported_token_type_message, "Invalid token type hint"

    translatable_method :oauth_already_in_use_message, "error generating unique token"
    auth_value_method :oauth_already_in_use_error_code, "invalid_request"
    auth_value_method :oauth_invalid_grant_type_error_code, "unsupported_grant_type"

    # Resource Server params
    # Only required to use if the plugin is to be used in a resource server
    auth_value_method :is_authorization_server?, true

    auth_value_methods(:only_json?)

    auth_value_method :json_request_regexp, %r{\bapplication/(?:vnd\.api\+)?json\b}i

    # METADATA
    auth_value_method :oauth_metadata_service_documentation, nil
    auth_value_method :oauth_metadata_ui_locales_supported, nil
    auth_value_method :oauth_metadata_op_policy_uri, nil
    auth_value_method :oauth_metadata_op_tos_uri, nil

    auth_value_methods(
      :fetch_access_token,
      :secret_hash,
      :generate_token_hash,
      :secret_matches?,
      :authorization_server_url,
      :oauth_unique_id_generator,
      :oauth_grants_unique_columns,
      :require_authorizable_account
    )

    # /token
    route(:token) do |r|
      next unless is_authorization_server?

      before_token_route
      require_oauth_application

      r.post do
        catch_error do
          validate_token_params

          oauth_grant = nil

          transaction do
            before_token
            oauth_grant = create_token(param("grant_type"))
          end

          json_response_success(json_access_token_payload(oauth_grant))
        end

        throw_json_response_error(oauth_invalid_response_status, "invalid_request")
      end
    end

    def oauth_server_metadata(issuer = nil)
      request.on(".well-known") do
        request.on("oauth-authorization-server") do
          request.get do
            json_response_success(oauth_server_metadata_body(issuer), true)
          end
        end
      end
    end

    def check_csrf?
      case request.path
      when token_path
        false
      else
        super
      end
    end

    # Overrides session_value, so that a valid authorization token also authenticates a request
    # TODO: deprecate
    def session_value
      super || oauth_token_subject
    end

    def oauth_token_subject
      return unless authorization_token

      # TODO: fix this once tokens know which type they were generated with
      authorization_token[oauth_grants_account_id_column] ||
        authorization_token[oauth_grants_oauth_application_id_column]
    end

    def accepts_json?
      return true if only_json?

      (accept = request.env["HTTP_ACCEPT"]) && accept =~ json_request_regexp
    end

    unless method_defined?(:json_request?)
      # copied from the jwt feature
      def json_request?
        return @json_request if defined?(@json_request)

        @json_request = request.content_type =~ json_request_regexp
      end
    end

    def scopes
      scope = request.params["scope"]
      case scope
      when Array
        scope
      when String
        scope.split(" ")
      end
    end

    def redirect_uri
      param_or_nil("redirect_uri") || begin
        return unless oauth_application

        redirect_uris = oauth_application[oauth_applications_redirect_uri_column].split(" ")
        redirect_uris.size == 1 ? redirect_uris.first : nil
      end
    end

    def oauth_application
      return @oauth_application if defined?(@oauth_application)

      @oauth_application = begin
        client_id = param_or_nil("client_id")

        return unless client_id

        db[oauth_applications_table].filter(oauth_applications_client_id_column => client_id).first
      end
    end

    def fetch_access_token
      value = request.env["HTTP_AUTHORIZATION"]

      return unless value && !value.empty?

      scheme, token = value.split(" ", 2)

      return unless scheme.downcase == oauth_token_type

      return if token.nil? || token.empty?

      token
    end

    def authorization_token
      return @authorization_token if defined?(@authorization_token)

      # check if there is a token
      bearer_token = fetch_access_token

      return unless bearer_token

      @authorization_token = if is_authorization_server?
                               # check if token has not expired
                               # check if token has been revoked
                               oauth_grant_by_token(bearer_token)
                             else
                               # where in resource server, NOT the authorization server.
                               payload = introspection_request("access_token", bearer_token)

                               return unless payload["active"]

                               payload
                             end
    end

    def require_oauth_authorization(*scopes)
      authorization_required unless authorization_token

      token_scopes = if is_authorization_server?
                       authorization_token[oauth_grants_scopes_column].split(oauth_scope_separator)
                     else
                       aux_scopes = authorization_token["scope"]
                       if aux_scopes
                         aux_scopes.split(oauth_scope_separator)
                       else
                         []
                       end
                     end

      authorization_required unless scopes.any? { |scope| token_scopes.include?(scope) }
    end

    def use_date_arithmetic?
      true
    end

    def post_configure
      super

      # all of the extensions below involve DB changes. Resource server mode doesn't use
      # database functions for OAuth though.
      return unless is_authorization_server?

      self.class.__send__(:include, Rodauth::OAuth::ExtendDatabase(db))

      # Check whether we can reutilize db entries for the same account / application pair
      one_oauth_token_per_account = db.indexes(oauth_grants_table).values.any? do |definition|
        definition[:unique] &&
          definition[:columns] == oauth_grants_unique_columns
      end

      self.class.send(:define_method, :__one_oauth_token_per_account) { one_oauth_token_per_account }

      i18n_register(File.expand_path(File.join(__dir__, "..", "..", "..", "locales"))) if features.include?(:i18n)
    end

    private

    def require_authorizable_account
      require_account
    end

    def rescue_from_uniqueness_error(&block)
      retries = oauth_unique_id_generation_retries
      begin
        transaction(savepoint: :only, &block)
      rescue Sequel::UniqueConstraintViolation
        redirect_response_error("already_in_use") if retries.zero?
        retries -= 1
        retry
      end
    end

    # OAuth Token Unique/Reuse
    def oauth_grants_unique_columns
      [
        oauth_grants_oauth_application_id_column,
        oauth_grants_account_id_column,
        oauth_grants_scopes_column
      ]
    end

    def authorization_server_url
      base_url
    end

    def template_path(page)
      path = File.join(File.dirname(__FILE__), "../../../templates", "#{page}.str")
      return super unless File.exist?(path)

      path
    end

    # to be used internally. Same semantics as require account, must:
    # fetch an authorization basic header
    # parse client id and secret
    #
    def require_oauth_application
      # get client credentials
      auth_method = nil
      client_id = client_secret = nil

      if (token = ((v = request.env["HTTP_AUTHORIZATION"]) && v[/\A *Basic (.*)\Z/, 1]))
        # client_secret_basic
        client_id, client_secret = Base64.decode64(token).split(/:/, 2)
        auth_method = "client_secret_basic"
      else
        # client_secret_post
        client_id = param_or_nil("client_id")
        client_secret = param_or_nil("client_secret")
        auth_method = "client_secret_post" if client_secret
      end

      authorization_required unless client_id

      @oauth_application = db[oauth_applications_table].where(oauth_applications_client_id_column => client_id).first

      authorization_required unless @oauth_application

      authorization_required unless authorized_oauth_application?(@oauth_application, client_secret, auth_method)
    end

    def authorized_oauth_application?(oauth_application, client_secret, auth_method)
      supported_auth_methods = if oauth_application[oauth_applications_token_endpoint_auth_method_column]
                                 oauth_application[oauth_applications_token_endpoint_auth_method_column].split(/ +/)
                               else
                                 oauth_auth_methods_supported
                               end

      if auth_method
        supported_auth_methods.include?(auth_method) && secret_matches?(oauth_application, client_secret)
      else
        supported_auth_methods.include?("none")
      end
    end

    def no_auth_oauth_application?(_oauth_application)
      supported_auth_methods.include?("none")
    end

    def require_oauth_application_from_account
      ds = db[oauth_applications_table]
           .join(oauth_grants_table, Sequel[oauth_grants_table][oauth_grants_oauth_application_id_column] =>
                                     Sequel[oauth_applications_table][oauth_applications_id_column])
           .where(oauth_grant_by_token_ds(param("token")).opts.fetch(:where, true))
           .where(Sequel[oauth_applications_table][oauth_applications_account_id_column] => account_id)

      @oauth_application = ds.qualify.first
      return if @oauth_application

      set_redirect_error_flash revoke_unauthorized_account_error_flash
      redirect request.referer || "/"
    end

    def secret_matches?(oauth_application, secret)
      BCrypt::Password.new(oauth_application[oauth_applications_client_secret_column]) == secret
    end

    def secret_hash(secret)
      password_hash(secret)
    end

    def oauth_unique_id_generator
      SecureRandom.urlsafe_base64(32)
    end

    def generate_token_hash(token)
      Base64.urlsafe_encode64(Digest::SHA256.digest(token))
    end

    def grant_from_application?(oauth_grant, oauth_application)
      oauth_grant[oauth_grants_oauth_application_id_column] == oauth_application[oauth_applications_id_column]
    end

    unless method_defined?(:password_hash)
      # From login_requirements_base feature

      def password_hash(password)
        BCrypt::Password.create(password, cost: BCrypt::Engine::DEFAULT_COST)
      end
    end

    def generate_token(grant_params = {}, should_generate_refresh_token = true)
      if grant_params[oauth_grants_id_column] && (oauth_reuse_access_token &&
           (
             if oauth_grants_token_hash_column
               grant_params[oauth_grants_token_hash_column]
             else
               grant_params[oauth_grants_token_column]
             end
           ))
        return grant_params
      end

      # grant_params = { oauth_grants_id_column => grant_params[oauth_grants_id_column] }

      update_params = {
        oauth_grants_expires_in_column => Sequel.date_add(Sequel::CURRENT_TIMESTAMP, seconds: oauth_token_expires_in),
        oauth_grants_code_column => nil
      }

      rescue_from_uniqueness_error do
        access_token = _generate_access_token(update_params)
        refresh_token = _generate_refresh_token(update_params) if should_generate_refresh_token
        oauth_grant = store_token(grant_params, update_params)

        return unless oauth_grant

        oauth_grant[oauth_grants_token_column] = access_token
        oauth_grant[oauth_grants_refresh_token_column] = refresh_token if refresh_token
        oauth_grant
      end
    end

    def _generate_access_token(params = {})
      token = oauth_unique_id_generator

      if oauth_grants_token_hash_column
        params[oauth_grants_token_hash_column] = generate_token_hash(token)
      else
        params[oauth_grants_token_column] = token
      end

      token
    end

    def _generate_refresh_token(params)
      token = oauth_unique_id_generator

      if oauth_grants_refresh_token_hash_column
        params[oauth_grants_refresh_token_hash_column] = generate_token_hash(token)
      else
        params[oauth_grants_refresh_token_column] = token
      end

      token
    end

    def _grant_with_access_token?(oauth_grant)
      if oauth_grants_token_hash_column
        oauth_grant[oauth_grants_token_hash_column]
      else
        oauth_grant[oauth_grants_token_column]
      end
    end

    def store_token(grant_params, update_params = {})
      ds = db[oauth_grants_table]

      if __one_oauth_token_per_account

        to_update_if_null = [
          oauth_grants_token_column,
          oauth_grants_token_hash_column,
          oauth_grants_refresh_token_column,
          oauth_grants_refresh_token_hash_column
        ].compact.map do |attribute|
          [
            attribute,
            (
              if ds.respond_to?(:supports_insert_conflict?) && ds.supports_insert_conflict?
                Sequel.function(:coalesce, Sequel[oauth_grants_table][attribute], Sequel[:excluded][attribute])
              else
                Sequel.function(:coalesce, Sequel[oauth_grants_table][attribute], update_params[attribute])
              end
            )
          ]
        end

        token = __insert_or_update_and_return__(
          ds,
          oauth_grants_id_column,
          oauth_grants_unique_columns,
          grant_params.merge(update_params),
          Sequel.expr(Sequel[oauth_grants_table][oauth_grants_expires_in_column]) > Sequel::CURRENT_TIMESTAMP,
          Hash[to_update_if_null]
        )

        # if the previous operation didn't return a row, it means that the conditions
        # invalidated the update, and the existing token is still valid.
        token || ds.where(
          oauth_grants_account_id_column => update_params[oauth_grants_account_id_column],
          oauth_grants_oauth_application_id_column => update_params[oauth_grants_oauth_application_id_column]
        ).first
      else

        if oauth_reuse_access_token
          unique_conds = Hash[oauth_grants_unique_columns.map { |column| [column, update_params[column]] }]
          valid_token_ds = valid_oauth_grant_ds(unique_conds)
          if oauth_grants_token_hash_column
            valid_token_ds.exclude(oauth_grants_token_hash_column => nil)
          else
            valid_token_ds.exclude(oauth_grants_token_column => nil)
          end

          valid_token = valid_token_ds.first

          return valid_token if valid_token
        end

        if grant_params[oauth_grants_id_column]
          __update_and_return__(ds.where(oauth_grants_id_column => grant_params[oauth_grants_id_column]), update_params)
        else
          __insert_and_return__(ds, oauth_grants_id_column, grant_params.merge(update_params))
        end
      end
    end

    def valid_locked_oauth_grant(grant_params = nil)
      oauth_grant = valid_oauth_grant_ds(grant_params).for_update.first

      redirect_response_error("invalid_grant") unless oauth_grant

      oauth_grant
    end

    def valid_oauth_grant_ds(grant_params = nil)
      ds = db[oauth_grants_table]
           .where(Sequel[oauth_grants_table][oauth_grants_revoked_at_column] => nil)
           .where(Sequel.expr(Sequel[oauth_grants_table][oauth_grants_expires_in_column]) >= Sequel::CURRENT_TIMESTAMP)
      ds = ds.where(grant_params) if grant_params

      ds
    end

    def oauth_grant_by_token_ds(token)
      ds = valid_oauth_grant_ds

      if oauth_grants_token_hash_column
        ds.where(Sequel[oauth_grants_table][oauth_grants_token_hash_column] => generate_token_hash(token))
      else
        ds.where(Sequel[oauth_grants_table][oauth_grants_token_column] => token)
      end
    end

    def oauth_grant_by_token(token)
      oauth_grant_by_token_ds(token).first
    end

    def oauth_grant_by_refresh_token(token, revoked: false)
      ds = db[oauth_grants_table].where(oauth_grants_oauth_application_id_column => oauth_application[oauth_applications_id_column])
      #
      # filter expired refresh tokens out.
      # an expired refresh token is a token whose access token expired for a period longer than the
      # refresh token expiration period.
      #
      ds = ds.where(Sequel.date_add(oauth_grants_expires_in_column, seconds: oauth_refresh_token_expires_in) >= Sequel::CURRENT_TIMESTAMP)

      ds = if oauth_grants_refresh_token_hash_column
             ds.where(oauth_grants_refresh_token_hash_column => generate_token_hash(token))
           else
             ds.where(oauth_grants_refresh_token_column => token)
           end

      ds = ds.where(oauth_grants_revoked_at_column => nil) unless revoked

      ds.first
    end

    def json_access_token_payload(oauth_grant)
      payload = {
        "access_token" => oauth_grant[oauth_grants_token_column],
        "token_type" => oauth_token_type,
        "expires_in" => oauth_token_expires_in
      }
      payload["refresh_token"] = oauth_grant[oauth_grants_refresh_token_column] if oauth_grant[oauth_grants_refresh_token_column]
      payload
    end

    # Access Tokens

    def validate_token_params
      unless (grant_type = param_or_nil("grant_type"))
        redirect_response_error("invalid_request")
      end

      redirect_response_error("invalid_request") if grant_type == "refresh_token" && !param_or_nil("refresh_token")
    end

    def create_token(grant_type)
      redirect_response_error("invalid_request") unless supported_grant_type?(grant_type, "refresh_token")

      refresh_token = param("refresh_token")
      # fetch potentially revoked oauth token
      oauth_grant = oauth_grant_by_refresh_token(refresh_token, revoked: true)

      update_params = { oauth_grants_expires_in_column => Sequel.date_add(Sequel::CURRENT_TIMESTAMP, seconds: oauth_token_expires_in) }

      if !oauth_grant || oauth_grant[oauth_grants_revoked_at_column]
        redirect_response_error("invalid_grant")
      elsif oauth_refresh_token_protection_policy == "rotation"
        # https://tools.ietf.org/html/draft-ietf-oauth-v2-1-00#section-6.1
        #
        # If a refresh token is compromised and subsequently used by both the attacker and the legitimate
        # client, one of them will present an invalidated refresh token, which will inform the authorization
        # server of the breach.  The authorization server cannot determine which party submitted the invalid
        # refresh token, but it will revoke the active refresh token.  This stops the attack at the cost of
        # forcing the legitimate client to obtain a fresh authorization grant.

        refresh_token = _generate_refresh_token(update_params)
      end

      update_params[oauth_grants_oauth_application_id_column] = oauth_grant[oauth_grants_oauth_application_id_column]

      oauth_grant = create_token_from_token(oauth_grant, update_params)
      oauth_grant[oauth_grants_refresh_token_column] = refresh_token
      oauth_grant
    end

    def create_token_from_token(oauth_grant, update_params)
      redirect_response_error("invalid_grant") unless grant_from_application?(oauth_grant, oauth_application)

      rescue_from_uniqueness_error do
        oauth_grants_ds = db[oauth_grants_table].where(oauth_grants_id_column => oauth_grant[oauth_grants_id_column])
        access_token = _generate_access_token(update_params)
        oauth_grant = __update_and_return__(oauth_grants_ds, update_params)

        oauth_grant[oauth_grants_token_column] = access_token
        oauth_grant
      end
    end

    def supported_grant_type?(grant_type, expected_grant_type = grant_type)
      return false unless grant_type == expected_grant_type

      return true unless (grant_types_supported = oauth_application[oauth_applications_grant_types_column])

      grant_types_supported = grant_types_supported.split(/ +/)

      grant_types_supported.include?(grant_type)
    end

    def oauth_server_metadata_body(path = nil)
      issuer = base_url
      issuer += "/#{path}" if path

      {
        issuer: issuer,
        token_endpoint: token_url,
        scopes_supported: oauth_application_scopes,
        response_types_supported: [],
        response_modes_supported: [],
        grant_types_supported: %w[refresh_token],
        token_endpoint_auth_methods_supported: oauth_auth_methods_supported,
        service_documentation: oauth_metadata_service_documentation,
        ui_locales_supported: oauth_metadata_ui_locales_supported,
        op_policy_uri: oauth_metadata_op_policy_uri,
        op_tos_uri: oauth_metadata_op_tos_uri
      }
    end

    def redirect_response_error(error_code, redirect_url = redirect_uri || request.referer || default_redirect)
      if accepts_json?
        status_code = if respond_to?(:"oauth_#{error_code}_response_status")
                        send(:"oauth_#{error_code}_response_status")
                      else
                        oauth_invalid_response_status
                      end

        throw_json_response_error(status_code, error_code)
      else
        redirect_url = URI.parse(redirect_url)
        query_params = []

        query_params << if respond_to?(:"oauth_#{error_code}_error_code")
                          "error=#{send(:"oauth_#{error_code}_error_code")}"
                        else
                          "error=#{error_code}"
                        end

        if respond_to?(:"oauth_#{error_code}_message")
          message = send(:"oauth_#{error_code}_message")
          query_params << ["error_description=#{CGI.escape(message)}"]
        end

        query_params << redirect_url.query if redirect_url.query
        redirect_url.query = query_params.join("&")
        redirect(redirect_url.to_s)
      end
    end

    def json_response_success(body, cache = false)
      response.status = 200
      response["Content-Type"] ||= json_response_content_type
      if cache
        # defaulting to 1-day for everyone, for now at least
        max_age = 60 * 60 * 24
        response["Cache-Control"] = "private, max-age=#{max_age}"
      else
        response["Cache-Control"] = "no-store"
        response["Pragma"] = "no-cache"
      end
      json_payload = _json_response_body(body)
      return_response(json_payload)
    end

    def throw_json_response_error(status, error_code, message = nil)
      set_response_error_status(status)
      code = if respond_to?(:"oauth_#{error_code}_error_code")
               send(:"oauth_#{error_code}_error_code")
             else
               error_code
             end
      payload = { "error" => code }
      payload["error_description"] = message || (send(:"oauth_#{error_code}_message") if respond_to?(:"oauth_#{error_code}_message"))
      json_payload = _json_response_body(payload)
      response["Content-Type"] ||= json_response_content_type
      response["WWW-Authenticate"] = oauth_token_type.upcase if status == 401
      return_response(json_payload)
    end

    unless method_defined?(:_json_response_body)
      def _json_response_body(hash)
        if request.respond_to?(:convert_to_json)
          request.send(:convert_to_json, hash)
        else
          JSON.dump(hash)
        end
      end
    end

    if Gem::Version.new(Rodauth.version) < Gem::Version.new("2.23")
      def return_response(body = nil)
        response.write(body) if body
        request.halt
      end
    end

    def authorization_required
      throw_json_response_error(oauth_authorization_required_error_status, "invalid_client")
    end

    def check_valid_scopes?
      return false unless scopes

      (scopes - oauth_application[oauth_applications_scopes_column].split(oauth_scope_separator)).empty?
    end

    def check_valid_uri?(uri)
      URI::DEFAULT_PARSER.make_regexp(oauth_valid_uri_schemes).match?(uri)
    end

    # Resource server mode

    def authorization_server_metadata
      auth_url = URI(authorization_server_url).dup
      auth_url.path = "/.well-known/oauth-authorization-server"

      http_request_with_cache(auth_url)
    end
  end
end
