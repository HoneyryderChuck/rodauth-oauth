# frozen-string-literal: true

module Rodauth
  Feature.define(:oidc, :Oidc) do
    # https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    OIDC_SCOPES_MAP = {
      "profile" => %i[name family_name given_name middle_name nickname preferred_username
                      profile picture website gender birthdate zoneinfo locale updated_at].freeze,
      "email" => %i[email email_verified].freeze,
      "address" => %i[formatted street_address locality region postal_code country].freeze,
      "phone" => %i[phone_number phone_number_verified].freeze
    }.freeze

    VALID_METADATA_KEYS = %i[
      issuer
      authorization_endpoint
      end_session_endpoint
      token_endpoint
      userinfo_endpoint
      jwks_uri
      registration_endpoint
      scopes_supported
      response_types_supported
      response_modes_supported
      grant_types_supported
      acr_values_supported
      subject_types_supported
      id_token_signing_alg_values_supported
      id_token_encryption_alg_values_supported
      id_token_encryption_enc_values_supported
      userinfo_signing_alg_values_supported
      userinfo_encryption_alg_values_supported
      userinfo_encryption_enc_values_supported
      request_object_signing_alg_values_supported
      request_object_encryption_alg_values_supported
      request_object_encryption_enc_values_supported
      token_endpoint_auth_methods_supported
      token_endpoint_auth_signing_alg_values_supported
      display_values_supported
      claim_types_supported
      claims_supported
      service_documentation
      claims_locales_supported
      ui_locales_supported
      claims_parameter_supported
      request_parameter_supported
      request_uri_parameter_supported
      require_request_uri_registration
      op_policy_uri
      op_tos_uri
    ].freeze

    REQUIRED_METADATA_KEYS = %i[
      issuer
      authorization_endpoint
      token_endpoint
      jwks_uri
      response_types_supported
      subject_types_supported
      id_token_signing_alg_values_supported
    ].freeze

    depends :oauth_jwt

    auth_value_method :oauth_application_default_scope, "openid"
    auth_value_method :oauth_application_scopes, %w[openid]

    auth_value_method :oauth_grants_nonce_column, :nonce
    auth_value_method :oauth_tokens_nonce_column, :nonce

    translatable_method :invalid_scope_message, "The Access Token expired"

    auth_value_method :webfinger_relation, "http://openid.net/specs/connect/1.0/issuer"

    auth_value_method :oauth_prompt_login_cookie_key, "_rodauth_oauth_prompt_login"
    auth_value_method :oauth_prompt_login_cookie_options, {}.freeze
    auth_value_method :oauth_prompt_login_interval, 5 * 60 * 60 # 5 minutes

    # logout
    auth_value_method :oauth_applications_post_logout_redirect_uri_column, :post_logout_redirect_uri
    auth_value_method :use_rp_initiated_logout?, false

    auth_value_methods(:get_oidc_param, :get_additional_param)

    # /userinfo
    route(:userinfo) do |r|
      next unless is_authorization_server?

      r.on method: %i[get post] do
        catch_error do
          oauth_token = authorization_token

          throw_json_response_error(authorization_required_error_status, "invalid_token") unless oauth_token

          oauth_scopes = oauth_token["scope"].split(" ")

          throw_json_response_error(authorization_required_error_status, "invalid_token") unless oauth_scopes.include?("openid")

          account = db[accounts_table].where(account_id_column => oauth_token["sub"]).first

          throw_json_response_error(authorization_required_error_status, "invalid_token") unless account

          oauth_scopes.delete("openid")

          oidc_claims = { "sub" => oauth_token["sub"] }

          fill_with_account_claims(oidc_claims, account, oauth_scopes)

          json_response_success(oidc_claims)
        end

        throw_json_response_error(authorization_required_error_status, "invalid_token")
      end
    end

    # /oidc-logout
    route(:oidc_logout) do |r|
      next unless use_rp_initiated_logout?

      before_oidc_logout_route
      require_authorizable_account

      # OpenID Providers MUST support the use of the HTTP GET and POST methods
      r.on method: %i[get post] do
        catch_error do
          validate_oidc_logout_params

          #
          # why this is done:
          #
          # we need to decode the id token in order to get the application, because, if the
          # signing key is application-specific, we don't know how to verify the signature
          # beforehand. Hence, we have to do it twice: decode-and-do-not-verify, initialize
          # the @oauth_application, and then decode-and-verify.
          #
          oauth_token = jwt_decode(param("id_token_hint"), verify_claims: false)
          oauth_application_id = oauth_token["client_id"]

          # check whether ID token belongs to currently logged-in user
          redirect_response_error("invalid_request") unless oauth_token["sub"] == jwt_subject(
            oauth_tokens_account_id_column => account_id,
            oauth_tokens_oauth_application_id_column => oauth_application_id
          )

          # When an id_token_hint parameter is present, the OP MUST validate that it was the issuer of the ID Token.
          redirect_response_error("invalid_request") unless oauth_token && oauth_token["iss"] == issuer

          # now let's logout from IdP
          transaction do
            before_logout
            logout
            after_logout
          end

          if (post_logout_redirect_uri = param_or_nil("post_logout_redirect_uri"))
            catch(:default_logout_redirect) do
              oauth_application = db[oauth_applications_table].where(oauth_applications_client_id_column => oauth_token["client_id"]).first

              throw(:default_logout_redirect) unless oauth_application

              post_logout_redirect_uris = oauth_application[oauth_applications_post_logout_redirect_uri_column].split(" ")

              throw(:default_logout_redirect) unless post_logout_redirect_uris.include?(post_logout_redirect_uri)

              if (state = param_or_nil("state"))
                post_logout_redirect_uri = URI(post_logout_redirect_uri)
                params = ["state=#{state}"]
                params << post_logout_redirect_uri.query if post_logout_redirect_uri.query
                post_logout_redirect_uri.query = params.join("&")
                post_logout_redirect_uri = post_logout_redirect_uri.to_s
              end

              redirect(post_logout_redirect_uri)
            end

          end

          # regular logout procedure
          set_notice_flash(logout_notice_flash)
          redirect(logout_redirect)
        end

        redirect_response_error("invalid_request")
      end
    end

    def openid_configuration(alt_issuer = nil)
      request.on(".well-known/openid-configuration") do
        allow_cors(request)

        request.get do
          json_response_success(openid_configuration_body(alt_issuer), cache: true)
        end
      end
    end

    def webfinger
      request.on(".well-known/webfinger") do
        request.get do
          resource = param_or_nil("resource")

          throw_json_response_error(400, "invalid_request") unless resource

          response.status = 200
          response["Content-Type"] ||= "application/jrd+json"

          json_payload = JSON.dump({
                                     subject: resource,
                                     links: [{
                                       rel: webfinger_relation,
                                       href: authorization_server_url
                                     }]
                                   })
          response.write(json_payload)
          request.halt
        end
      end
    end

    def check_csrf?
      case request.path
      when userinfo_path
        false
      else
        super
      end
    end

    private

    def require_authorizable_account
      try_prompt if param_or_nil("prompt")
      super
    end

    # this executes before checking for a logged in account
    def try_prompt
      prompt = param_or_nil("prompt")

      case prompt
      when "none"
        redirect_response_error("login_required") unless logged_in?

        require_account

        if db[oauth_grants_table].where(
          oauth_grants_account_id_column => account_id,
          oauth_grants_oauth_application_id_column => oauth_application[oauth_applications_id_column],
          oauth_grants_redirect_uri_column => redirect_uri,
          oauth_grants_scopes_column => scopes.join(oauth_scope_separator),
          oauth_grants_access_type_column => "online"
        ).count.zero?
          redirect_response_error("consent_required")
        end

        request.env["REQUEST_METHOD"] = "POST"
      when "login"
        if logged_in? && request.cookies[oauth_prompt_login_cookie_key] == "login"
          ::Rack::Utils.delete_cookie_header!(response.headers, oauth_prompt_login_cookie_key, oauth_prompt_login_cookie_options)
          return
        end

        # logging out
        clear_session
        set_session_value(login_redirect_session_key, request.fullpath)

        login_cookie_opts = Hash[oauth_prompt_login_cookie_options]
        login_cookie_opts[:value] = "login"
        login_cookie_opts[:expires] = convert_timestamp(Time.now + oauth_prompt_login_interval) # 15 minutes
        ::Rack::Utils.set_cookie_header!(response.headers, oauth_prompt_login_cookie_key, login_cookie_opts)

        redirect require_login_redirect
      when "consent"
        require_account

        if db[oauth_grants_table].where(
          oauth_grants_account_id_column => account_id,
          oauth_grants_oauth_application_id_column => oauth_application[oauth_applications_id_column],
          oauth_grants_redirect_uri_column => redirect_uri,
          oauth_grants_scopes_column => scopes.join(oauth_scope_separator),
          oauth_grants_access_type_column => "online"
        ).count.zero?
          redirect_response_error("consent_required")
        end
      when "select-account"
        # obly works if select_account plugin is available
        require_select_account if respond_to?(:require_select_account)
      else
        redirect_response_error("invalid_request")
      end
    end

    def create_oauth_grant(create_params = {})
      return super unless (nonce = param_or_nil("nonce"))

      super(oauth_grants_nonce_column => nonce)
    end

    def create_oauth_token_from_authorization_code(oauth_grant, create_params)
      return super unless oauth_grant[oauth_grants_nonce_column]

      super(oauth_grant, create_params.merge(oauth_tokens_nonce_column => oauth_grant[oauth_grants_nonce_column]))
    end

    def create_oauth_token(*)
      oauth_token = super
      generate_id_token(oauth_token)
      oauth_token
    end

    def generate_id_token(oauth_token)
      oauth_scopes = oauth_token[oauth_tokens_scopes_column].split(oauth_scope_separator)

      return unless oauth_scopes.include?("openid")

      id_token_claims = jwt_claims(oauth_token)
      id_token_claims[:nonce] = oauth_token[oauth_tokens_nonce_column] if oauth_token[oauth_tokens_nonce_column]

      # Time when the End-User authentication occurred.
      #
      # Sounds like the same as issued at claim.
      id_token_claims[:auth_time] = id_token_claims[:iat]

      account = db[accounts_table].where(account_id_column => oauth_token[oauth_tokens_account_id_column]).first

      # this should never happen!
      # a newly minted oauth token from a grant should have been assigned to an account
      # who just authorized its generation.
      return unless account

      fill_with_account_claims(id_token_claims, account, oauth_scopes)

      oauth_token[:id_token] = jwt_encode(id_token_claims)
    end

    # aka fill_with_standard_claims
    def fill_with_account_claims(claims, account, scopes)
      scopes_by_claim = scopes.each_with_object({}) do |scope, by_oidc|
        next if scope == "openid"

        oidc, param = scope.split(".", 2)

        by_oidc[oidc] ||= []

        by_oidc[oidc] << param.to_sym if param
      end

      oidc_scopes, additional_scopes = scopes_by_claim.keys.partition { |key| OIDC_SCOPES_MAP.key?(key) }

      unless oidc_scopes.empty?
        if respond_to?(:get_oidc_param)
          oidc_scopes.each do |scope|
            scope_claims = claims
            params = scopes_by_claim[scope]
            params = params.empty? ? OIDC_SCOPES_MAP[scope] : (OIDC_SCOPES_MAP[scope] & params)

            scope_claims = (claims["address"] = {}) if scope == "address"
            params.each do |param|
              scope_claims[param] = __send__(:get_oidc_param, account, param)
            end
          end
        else
          warn "`get_oidc_param(account, claim)` must be implemented to use oidc scopes."
        end
      end

      return if additional_scopes.empty?

      if respond_to?(:get_additional_param)
        additional_scopes.each do |scope|
          claims[scope] = __send__(:get_additional_param, account, scope.to_sym)
        end
      else
        warn "`get_additional_param(account, claim)` must be implemented to use oidc scopes."
      end
    end

    def json_access_token_payload(oauth_token)
      payload = super
      payload["id_token"] = oauth_token[:id_token] if oauth_token[:id_token]
      payload
    end

    # Authorize

    def check_valid_response_type?
      case param_or_nil("response_type")
      when "none", "id_token",
           "code token", "code id_token", "id_token token", "code id_token token" # multiple
        true
      else
        super
      end
    end

    def do_authorize(response_params = {}, response_mode = param_or_nil("response_mode"))
      return super unless use_oauth_implicit_grant_type?

      case param("response_type")
      when "id_token"
        response_params.replace(_do_authorize_id_token)
      when "code token"
        redirect_response_error("invalid_request") unless use_oauth_implicit_grant_type?

        response_params.replace(_do_authorize_code.merge(_do_authorize_token))
      when "code id_token"
        response_params.replace(_do_authorize_code.merge(_do_authorize_id_token))
      when "id_token token"
        response_params.replace(_do_authorize_id_token.merge(_do_authorize_token))
      when "code id_token token"

        response_params.replace(_do_authorize_code.merge(_do_authorize_id_token).merge(_do_authorize_token))
      end
      response_mode ||= "fragment" unless response_params.empty?

      super(response_params, response_mode)
    end

    def _do_authorize_id_token
      create_params = {
        oauth_tokens_account_id_column => account_id,
        oauth_tokens_oauth_application_id_column => oauth_application[oauth_applications_id_column],
        oauth_tokens_scopes_column => scopes
      }
      oauth_token = generate_oauth_token(create_params, false)
      generate_id_token(oauth_token)
      params = json_access_token_payload(oauth_token)
      params.delete("access_token")
      params
    end

    # Logout

    def validate_oidc_logout_params
      redirect_response_error("invalid_request") unless param_or_nil("id_token_hint")
      # check if valid token hint type
      return unless (redirect_uri = param_or_nil("post_logout_redirect_uri"))

      return if check_valid_uri?(redirect_uri)

      redirect_response_error("invalid_request")
    end

    # Metadata

    def openid_configuration_body(path)
      metadata = oauth_server_metadata_body(path).select do |k, _|
        VALID_METADATA_KEYS.include?(k)
      end

      scope_claims = oauth_application_scopes.each_with_object([]) do |scope, claims|
        oidc, param = scope.split(".", 2)
        if param
          claims << param
        else
          oidc_claims = OIDC_SCOPES_MAP[oidc]
          claims.concat(oidc_claims) if oidc_claims
        end
      end

      scope_claims.unshift("auth_time") if last_account_login_at

      response_types_supported = metadata[:response_types_supported]
      if use_oauth_implicit_grant_type?
        response_types_supported += ["none", "id_token", "code token", "code id_token", "id_token token", "code id_token token"]
      end

      metadata.merge(
        userinfo_endpoint: userinfo_url,
        end_session_endpoint: (oidc_logout_url if use_rp_initiated_logout?),
        response_types_supported: response_types_supported,
        subject_types_supported: [oauth_jwt_subject_type],

        id_token_signing_alg_values_supported: metadata[:token_endpoint_auth_signing_alg_values_supported],
        id_token_encryption_alg_values_supported: [oauth_jwt_jwe_algorithm].compact,
        id_token_encryption_enc_values_supported: [oauth_jwt_jwe_encryption_method].compact,

        userinfo_signing_alg_values_supported: [],
        userinfo_encryption_alg_values_supported: [],
        userinfo_encryption_enc_values_supported: [],

        request_object_signing_alg_values_supported: [],
        request_object_encryption_alg_values_supported: [],
        request_object_encryption_enc_values_supported: [],

        # These Claim Types are described in Section 5.6 of OpenID Connect Core 1.0 [OpenID.Core].
        # Values defined by this specification are normal, aggregated, and distributed.
        # If omitted, the implementation supports only normal Claims.
        claim_types_supported: %w[normal],
        claims_supported: %w[sub iss iat exp aud] | scope_claims
      ).reject do |key, val|
        # Filter null values in optional items
        (!REQUIRED_METADATA_KEYS.include?(key.to_sym) && val.nil?) ||
          # Claims with zero elements MUST be omitted from the response
          (val.respond_to?(:empty?) && val.empty?)
      end
    end

    def allow_cors(request)
      return unless request.request_method == "OPTIONS"

      response["Access-Control-Allow-Origin"] = "*"
      response["Access-Control-Allow-Methods"] = "GET, OPTIONS"
      response["Access-Control-Max-Age"] = "3600"
      response.status = 200
      request.halt
    end
  end
end
