# frozen_string_literal: true

require "rodauth/oauth"

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
      backchannel_logout_session_supported
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

    depends :account_expiration, :oauth_jwt, :oauth_jwt_jwks, :oauth_authorization_code_grant

    auth_value_method :oauth_application_scopes, %w[openid]

    %i[
      subject_type application_type sector_identifier_uri initiate_login_uri
      id_token_signed_response_alg id_token_encrypted_response_alg id_token_encrypted_response_enc
      userinfo_signed_response_alg userinfo_encrypted_response_alg userinfo_encrypted_response_enc
    ].each do |column|
      auth_value_method :"oauth_applications_#{column}_column", column
    end

    %i[nonce acr claims_locales claims].each do |column|
      auth_value_method :"oauth_grants_#{column}_column", column
    end

    auth_value_method :oauth_jwt_subject_type, "public" # fallback subject type: public, pairwise
    auth_value_method :oauth_jwt_subject_secret, nil # salt for pairwise generation

    translatable_method :oauth_invalid_scope_message, "The Access Token expired"

    auth_value_method :oauth_prompt_login_cookie_key, "_rodauth_oauth_prompt_login"
    auth_value_method :oauth_prompt_login_cookie_options, {}.freeze
    auth_value_method :oauth_prompt_login_interval, 5 * 60 * 60 # 5 minutes

    auth_value_methods(
      :userinfo_signing_alg_values_supported,
      :userinfo_encryption_alg_values_supported,
      :userinfo_encryption_enc_values_supported,
      :request_object_signing_alg_values_supported,
      :request_object_encryption_alg_values_supported,
      :request_object_encryption_enc_values_supported,
      :oauth_acr_values_supported,
      :get_oidc_account_last_login_at,
      :oidc_authorize_on_prompt_none?,
      :fill_with_account_claims,
      :get_oidc_param,
      :get_additional_param,
      :require_acr_value_phr,
      :require_acr_value_phrh,
      :require_acr_value,
      :json_webfinger_payload
    )

    # /userinfo
    auth_server_route(:userinfo) do |r|
      r.on method: %i[get post] do
        catch_error do
          claims = authorization_token

          throw_json_response_error(oauth_authorization_required_error_status, "invalid_token") unless claims

          oauth_scopes = claims["scope"].split(" ")

          throw_json_response_error(oauth_authorization_required_error_status, "invalid_token") unless oauth_scopes.include?("openid")

          account = account_ds(claims["sub"]).first

          throw_json_response_error(oauth_authorization_required_error_status, "invalid_token") unless account

          oauth_scopes.delete("openid")

          oidc_claims = { "sub" => claims["sub"] }

          @oauth_application = db[oauth_applications_table].where(oauth_applications_client_id_column => claims["client_id"]).first

          throw_json_response_error(oauth_authorization_required_error_status, "invalid_token") unless @oauth_application

          oauth_grant = valid_oauth_grant_ds(
            oauth_grants_oauth_application_id_column => @oauth_application[oauth_applications_id_column],
            **resource_owner_params_from_jwt_claims(claims)
          ).first

          claims_locales = oauth_grant[oauth_grants_claims_locales_column] if oauth_grant

          if (claims = oauth_grant[oauth_grants_claims_column])
            claims = JSON.parse(claims)
            if (userinfo_essential_claims = claims["userinfo"])
              oauth_scopes |= userinfo_essential_claims.to_a
            end
          end

          # 5.4 - The Claims requested by the profile, email, address, and phone scope values are returned from the UserInfo Endpoint
          fill_with_account_claims(oidc_claims, account, oauth_scopes, claims_locales)

          if (algo = @oauth_application[oauth_applications_userinfo_signed_response_alg_column])
            params = {
              jwks: oauth_application_jwks(@oauth_application),
              encryption_algorithm: @oauth_application[oauth_applications_userinfo_encrypted_response_alg_column],
              encryption_method: @oauth_application[oauth_applications_userinfo_encrypted_response_enc_column]
            }.compact

            jwt = jwt_encode(
              oidc_claims.merge(
                # If signed, the UserInfo Response SHOULD contain the Claims iss (issuer) and aud (audience) as members. The iss value
                # SHOULD be the OP's Issuer Identifier URL. The aud value SHOULD be or include the RP's Client ID value.
                iss: oauth_jwt_issuer,
                aud: @oauth_application[oauth_applications_client_id_column]
              ),
              signing_algorithm: algo,
              **params
            )
            jwt_response_success(jwt)
          else
            json_response_success(oidc_claims)
          end
        end

        throw_json_response_error(oauth_authorization_required_error_status, "invalid_token")
      end
    end

    def load_openid_configuration_route(alt_issuer = nil)
      request.on(".well-known/openid-configuration") do
        allow_cors(request)

        request.is do
          request.get do
            json_response_success(openid_configuration_body(alt_issuer), cache: true)
          end
        end
      end
    end

    def load_webfinger_route
      request.on(".well-known/webfinger") do
        request.get do
          resource = param_or_nil("resource")

          throw_json_response_error(400, "invalid_request") unless resource

          response.status = 200
          response["Content-Type"] ||= "application/jrd+json"

          return_response(json_webfinger_payload)
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

    def oauth_response_types_supported
      grant_types = oauth_grant_types_supported
      oidc_response_types = %w[id_token none]
      oidc_response_types |= ["code id_token"] if grant_types.include?("authorization_code")
      oidc_response_types |= ["code token", "id_token token", "code id_token token"] if grant_types.include?("implicit")
      super | oidc_response_types
    end

    def current_oauth_account
      subject_type = current_oauth_application[oauth_applications_subject_type_column] || oauth_jwt_subject_type

      return super unless subject_type == "pairwise"
    end

    private

    if defined?(::I18n)
      def before_authorize_route
        if (ui_locales = param_or_nil("ui_locales"))
          ui_locales = ui_locales.split(" ").map(&:to_sym)
          ui_locales &= ::I18n.available_locales

          ::I18n.locale = ui_locales.first unless ui_locales.empty?
        end

        super
      end
    end

    def userinfo_signing_alg_values_supported
      oauth_jwt_jws_algorithms_supported
    end

    def userinfo_encryption_alg_values_supported
      oauth_jwt_jwe_algorithms_supported
    end

    def userinfo_encryption_enc_values_supported
      oauth_jwt_jwe_encryption_methods_supported
    end

    def request_object_signing_alg_values_supported
      oauth_jwt_jws_algorithms_supported
    end

    def request_object_encryption_alg_values_supported
      oauth_jwt_jwe_algorithms_supported
    end

    def request_object_encryption_enc_values_supported
      oauth_jwt_jwe_encryption_methods_supported
    end

    def oauth_acr_values_supported
      acr_values = []
      acr_values << "phrh" if features.include?(:webauthn_login)
      acr_values << "phr" if respond_to?(:require_two_factor_authenticated)
      acr_values
    end

    def oidc_authorize_on_prompt_none?(_account)
      false
    end

    def validate_authorize_params
      if (max_age = param_or_nil("max_age"))

        max_age = Integer(max_age)

        redirect_response_error("invalid_request") unless max_age.positive?

        if Time.now - get_oidc_account_last_login_at(session_value) > max_age
          # force user to re-login
          clear_session
          set_session_value(login_redirect_session_key, request.fullpath)
          redirect require_login_redirect
        end
      end

      if (claims = param_or_nil("claims"))
        # The value is a JSON object listing the requested Claims.
        claims = JSON.parse(claims)

        claims.each do |_, individual_claims|
          redirect_response_error("invalid_request") unless individual_claims.is_a?(Hash)

          individual_claims.each do |_, claim|
            redirect_response_error("invalid_request") unless claim.nil? || individual_claims.is_a?(Hash)
          end
        end
      end

      sc = scopes

      # MUST ensure that the prompt parameter contains consent
      # MUST ignore the offline_access request unless the Client
      # is using a response_type value that would result in an
      # Authorization Code
      if sc && sc.include?("offline_access") && !(param_or_nil("prompt") == "consent" && (
                (response_type = param_or_nil("response_type")) && response_type.split(" ").include?("code")
              ))
        sc.delete("offline_access")

        request.params["scope"] = sc.join(" ")
      end

      super

      return unless (response_type = param_or_nil("response_type"))
      return unless response_type.include?("id_token")

      redirect_response_error("invalid_request") unless param_or_nil("nonce")
    end

    def require_authorizable_account
      try_prompt
      super
      @acr = try_acr_values
    end

    def get_oidc_account_last_login_at(account_id)
      get_activity_timestamp(account_id, account_activity_last_activity_column)
    end

    def jwt_subject(oauth_grant, client_application = oauth_application)
      subject_type = client_application[oauth_applications_subject_type_column] || oauth_jwt_subject_type

      case subject_type
      when "public"
        super
      when "pairwise"
        identifier_uri = client_application[oauth_applications_sector_identifier_uri_column]

        unless identifier_uri
          identifier_uri = client_application[oauth_applications_redirect_uri_column]
          identifier_uri = identifier_uri.split(" ")
          # If the Client has not provided a value for sector_identifier_uri in Dynamic Client Registration
          # [OpenID.Registration], the Sector Identifier used for pairwise identifier calculation is the host
          # component of the registered redirect_uri. If there are multiple hostnames in the registered redirect_uris,
          # the Client MUST register a sector_identifier_uri.
          if identifier_uri.size > 1
            # return error message
          end
          identifier_uri = identifier_uri.first
        end

        identifier_uri = URI(identifier_uri).host

        account_ids = oauth_grant.values_at(oauth_grants_resource_owner_columns)
        values = [identifier_uri, *account_ids, oauth_jwt_subject_secret]
        Digest::SHA256.hexdigest(values.join)
      else
        raise StandardError, "unexpected subject (#{subject_type})"
      end
    end

    # this executes before checking for a logged in account
    def try_prompt
      return unless (prompt = param_or_nil("prompt"))

      case prompt
      when "none"
        return unless request.get?

        redirect_response_error("login_required") unless logged_in?

        require_account

        redirect_response_error("interaction_required") unless oidc_authorize_on_prompt_none?(account_from_session)

        request.env["REQUEST_METHOD"] = "POST"
      when "login"
        return unless request.get?

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
        return unless request.post?

        require_account

        sc = scopes || []

        redirect_response_error("consent_required") if sc.empty?

      when "select-account"
        return unless request.get?

        # only works if select_account plugin is available
        require_select_account if respond_to?(:require_select_account)
      else
        redirect_response_error("invalid_request")
      end
    end

    def try_acr_values
      return unless (acr_values = param_or_nil("acr_values"))

      acr_values.split(" ").each do |acr_value|
        next unless oauth_acr_values_supported.include?(acr_value)

        case acr_value
        when "phr"
          return acr_value if require_acr_value_phr
        when "phrh"
          return acr_value if require_acr_value_phrh
        else
          return acr_value if require_acr_value(acr_value)
        end
      end

      nil
    end

    def require_acr_value_phr
      return false unless respond_to?(:require_two_factor_authenticated)

      require_two_factor_authenticated
      true
    end

    def require_acr_value_phrh
      return false unless features.include?(:webauthn_login)

      require_acr_value_phr && two_factor_login_type_match?("webauthn")
    end

    def require_acr_value(_acr)
      true
    end

    def create_oauth_grant(create_params = {})
      create_params.replace(oidc_grant_params.merge(create_params))
      super
    end

    def create_oauth_grant_with_token(create_params = {})
      create_params.merge!(resource_owner_params)
      create_params[oauth_grants_type_column] = "hybrid"
      create_params[oauth_grants_expires_in_column] = Sequel.date_add(Sequel::CURRENT_TIMESTAMP, seconds: oauth_access_token_expires_in)
      authorization_code = create_oauth_grant(create_params)
      access_token = if oauth_jwt_access_tokens
                       _generate_jwt_access_token(create_params)
                     else
                       oauth_grant = valid_oauth_grant_ds.where(oauth_grants_code_column => authorization_code).first
                       _generate_access_token(oauth_grant)
                     end

      json_access_token_payload(oauth_grants_token_column => access_token).merge("code" => authorization_code)
    end

    def create_token(*)
      oauth_grant = super
      generate_id_token(oauth_grant)
      oauth_grant
    end

    def generate_id_token(oauth_grant, include_claims = false)
      oauth_scopes = oauth_grant[oauth_grants_scopes_column].split(oauth_scope_separator)

      return unless oauth_scopes.include?("openid")

      signing_algorithm = oauth_application[oauth_applications_id_token_signed_response_alg_column] ||
                          oauth_jwt_keys.keys.first

      id_claims = id_token_claims(oauth_grant, signing_algorithm)

      account = db[accounts_table].where(account_id_column => oauth_grant[oauth_grants_account_id_column]).first

      # this should never happen!
      # a newly minted oauth token from a grant should have been assigned to an account
      # who just authorized its generation.
      return unless account

      if (claims = oauth_grant[oauth_grants_claims_column])
        claims = JSON.parse(claims)
        if (id_token_essential_claims = claims["id_token"])
          oauth_scopes |= id_token_essential_claims.to_a

          include_claims = true
        end
      end

      # 5.4 - However, when no Access Token is issued (which is the case for the response_type value id_token),
      # the resulting Claims are returned in the ID Token.
      fill_with_account_claims(id_claims, account, oauth_scopes, param_or_nil("claims_locales")) if include_claims

      params = {
        jwks: oauth_application_jwks(oauth_application),
        signing_algorithm: signing_algorithm,
        encryption_algorithm: oauth_application[oauth_applications_id_token_encrypted_response_alg_column],
        encryption_method: oauth_application[oauth_applications_id_token_encrypted_response_enc_column]
      }.compact

      oauth_grant[:id_token] = jwt_encode(id_claims, **params)
    end

    def id_token_claims(oauth_grant, signing_algorithm)
      claims = jwt_claims(oauth_grant)

      claims[:nonce] = oauth_grant[oauth_grants_nonce_column] if oauth_grant[oauth_grants_nonce_column]

      claims[:acr] = oauth_grant[oauth_grants_acr_column] if oauth_grant[oauth_grants_acr_column]

      # Time when the End-User authentication occurred.
      claims[:auth_time] = get_oidc_account_last_login_at(oauth_grant[oauth_grants_account_id_column]).to_i

      # Access Token hash value.
      if (access_token = oauth_grant[oauth_grants_token_column])
        claims[:at_hash] = id_token_hash(access_token, signing_algorithm)
      end

      # code hash value.
      if (code = oauth_grant[oauth_grants_code_column])
        claims[:c_hash] = id_token_hash(code, signing_algorithm)
      end

      claims
    end

    # aka fill_with_standard_claims
    def fill_with_account_claims(claims, account, scopes, claims_locales)
      additional_claims_info = {}

      scopes_by_claim = scopes.each_with_object({}) do |scope, by_oidc|
        next if scope == "openid"

        if scope.is_a?(Array)
          # essential claims
          param, additional_info = scope

          param = param.to_sym

          oidc, = OIDC_SCOPES_MAP.find do |_, oidc_scopes|
            oidc_scopes.include?(param)
          end || param.to_s

          param = nil if oidc == param.to_s

          additional_claims_info[param] = additional_info
        else

          oidc, param = scope.split(".", 2)

          param = param.to_sym if param
        end

        by_oidc[oidc] ||= []

        by_oidc[oidc] << param.to_sym if param
      end

      oidc_scopes, additional_scopes = scopes_by_claim.keys.partition { |key| OIDC_SCOPES_MAP.key?(key) }

      claims_locales = claims_locales.split(" ").map(&:to_sym) if claims_locales

      unless oidc_scopes.empty?
        if respond_to?(:get_oidc_param)
          get_oidc_param = proxy_get_param(:get_oidc_param, claims, claims_locales, additional_claims_info)

          oidc_scopes.each do |scope|
            scope_claims = claims
            params = scopes_by_claim[scope]
            params = params.empty? ? OIDC_SCOPES_MAP[scope] : (OIDC_SCOPES_MAP[scope] & params)

            scope_claims = (claims["address"] = {}) if scope == "address"

            params.each do |param|
              get_oidc_param[account, param, scope_claims]
            end
          end
        else
          warn "`get_oidc_param(account, claim)` must be implemented to use oidc scopes."
        end
      end

      return if additional_scopes.empty?

      if respond_to?(:get_additional_param)
        get_additional_param = proxy_get_param(:get_additional_param, claims, claims_locales, additional_claims_info)

        additional_scopes.each do |scope|
          get_additional_param[account, scope.to_sym]
        end
      else
        warn "`get_additional_param(account, claim)` must be implemented to use oidc scopes."
      end
    end

    def proxy_get_param(get_param_func, claims, claims_locales, additional_claims_info)
      meth = method(get_param_func)
      if meth.arity == 2
        lambda do |account, param, cl = claims|
          additional_info = additional_claims_info[param] || EMPTY_HASH
          value = additional_info["value"] || meth[account, param]
          value = nil if additional_info["values"] && additional_info["values"].include?(value)
          cl[param] = value unless value.nil?
        end
      elsif claims_locales.nil?
        lambda do |account, param, cl = claims|
          additional_info = additional_claims_info[param] || EMPTY_HASH
          value = additional_info["value"] || meth[account, param, nil]
          value = nil if additional_info["values"] && additional_info["values"].include?(value)
          cl[param] = value unless value.nil?
        end
      else
        lambda do |account, param, cl = claims|
          claims_values = claims_locales.map do |locale|
            additional_info = additional_claims_info[param] || EMPTY_HASH
            value = additional_info["value"] || meth[account, param, locale]
            value = nil if additional_info["values"] && additional_info["values"].include?(value)
            value
          end.compact

          if claims_values.uniq.size == 1
            cl[param] = claims_values.first
          else
            claims_locales.zip(claims_values).each do |locale, value|
              cl["#{param}##{locale}"] = value if value
            end
          end
        end
      end
    end

    def json_access_token_payload(oauth_grant)
      payload = super
      payload["id_token"] = oauth_grant[:id_token] if oauth_grant[:id_token]
      payload
    end

    # Authorize

    def check_valid_response_type?
      case param_or_nil("response_type")
      when "none", "id_token", "code id_token" # multiple
        true
      when "code token", "id_token token", "code id_token token"
        supports_token_response_type?
      else
        super
      end
    end

    def supported_response_mode?(response_mode, *)
      return super unless response_mode == "none"

      param("response_type") == "none"
    end

    def supports_token_response_type?
      features.include?(:oauth_implicit_grant)
    end

    def do_authorize(response_params = {}, response_mode = param_or_nil("response_mode"))
      response_type = param("response_type")
      case response_type
      when "id_token"
        grant_params = oidc_grant_params
        generate_id_token(grant_params, true)
        response_params.replace("id_token" => grant_params[:id_token])
      when "code token"
        redirect_response_error("invalid_request") unless supports_token_response_type?

        response_params.replace(create_oauth_grant_with_token)
      when "code id_token"
        params = _do_authorize_code
        oauth_grant = valid_oauth_grant_ds.where(oauth_grants_code_column => params["code"]).first
        generate_id_token(oauth_grant)
        response_params.replace(
          "id_token" => oauth_grant[:id_token],
          "code" => params["code"]
        )
      when "id_token token"
        redirect_response_error("invalid_request") unless supports_token_response_type?

        grant_params = oidc_grant_params.merge(oauth_grants_type_column => "hybrid")
        oauth_grant = _do_authorize_token(grant_params)
        generate_id_token(oauth_grant)

        response_params.replace(json_access_token_payload(oauth_grant))
      when "code id_token token"
        redirect_response_error("invalid_request") unless supports_token_response_type?

        params = create_oauth_grant_with_token
        oauth_grant = valid_oauth_grant_ds.where(oauth_grants_code_column => params["code"]).first
        oauth_grant[oauth_grants_token_column] = params["access_token"]
        generate_id_token(oauth_grant)

        response_params.replace(params.merge("id_token" => oauth_grant[:id_token]))
      when "none"
        response_mode ||= "none"
      end
      response_mode ||= "fragment" unless response_params.empty?

      super(response_params, response_mode)
    end

    def oidc_grant_params
      grant_params = {
        **resource_owner_params,
        oauth_grants_oauth_application_id_column => oauth_application[oauth_applications_id_column],
        oauth_grants_scopes_column => scopes.join(oauth_scope_separator),
        oauth_grants_redirect_uri_column => param_or_nil("redirect_uri")
      }
      if (nonce = param_or_nil("nonce"))
        grant_params[oauth_grants_nonce_column] = nonce
      end
      grant_params[oauth_grants_acr_column] = @acr if @acr
      if (claims_locales = param_or_nil("claims_locales"))
        grant_params[oauth_grants_claims_locales_column] = claims_locales
      end
      if (claims = param_or_nil("claims"))
        grant_params[oauth_grants_claims_column] = claims
      end
      grant_params
    end

    def generate_token(grant_params = {}, should_generate_refresh_token = true)
      scopes = grant_params[oauth_grants_scopes_column].split(oauth_scope_separator)

      super(grant_params, scopes.include?("offline_access") && should_generate_refresh_token)
    end

    def authorize_response(params, mode)
      redirect_url = URI.parse(redirect_uri)
      redirect(redirect_url.to_s) if mode == "none"
      super
    end

    # Webfinger

    def json_webfinger_payload
      JSON.dump({
                  subject: param("resource"),
                  links: [{
                    rel: "http://openid.net/specs/connect/1.0/issuer",
                    href: authorization_server_url
                  }]
                })
    end

    # Metadata

    def openid_configuration_body(path = nil)
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

      scope_claims.unshift("auth_time")

      metadata.merge(
        userinfo_endpoint: userinfo_url,
        subject_types_supported: %w[public pairwise],
        acr_values_supported: oauth_acr_values_supported,
        claims_parameter_supported: true,

        id_token_signing_alg_values_supported: oauth_jwt_jws_algorithms_supported,
        id_token_encryption_alg_values_supported: oauth_jwt_jwe_algorithms_supported,
        id_token_encryption_enc_values_supported: oauth_jwt_jwe_encryption_methods_supported,

        userinfo_signing_alg_values_supported: oauth_jwt_jws_algorithms_supported,
        userinfo_encryption_alg_values_supported: oauth_jwt_jwe_algorithms_supported,
        userinfo_encryption_enc_values_supported: oauth_jwt_jwe_encryption_methods_supported,

        request_object_signing_alg_values_supported: oauth_jwt_jws_algorithms_supported,
        request_object_encryption_alg_values_supported: oauth_jwt_jwe_algorithms_supported,
        request_object_encryption_enc_values_supported: oauth_jwt_jwe_encryption_methods_supported,

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
      return_response
    end

    def jwt_response_success(jwt, cache = false)
      response.status = 200
      response["Content-Type"] ||= "application/jwt"
      if cache
        # defaulting to 1-day for everyone, for now at least
        max_age = 60 * 60 * 24
        response["Cache-Control"] = "private, max-age=#{max_age}"
      else
        response["Cache-Control"] = "no-store"
        response["Pragma"] = "no-cache"
      end
      return_response(jwt)
    end

    def id_token_hash(hash, algo)
      digest = case algo
               when /256/ then Digest::SHA256
               when /384/ then Digest::SHA384
               when /512/ then Digest::SHA512
               end

      return unless digest

      hash = digest.digest(hash)
      hash = hash[0...hash.size / 2]
      Base64.urlsafe_encode64(hash).tr("=", "")
    end
  end
end
