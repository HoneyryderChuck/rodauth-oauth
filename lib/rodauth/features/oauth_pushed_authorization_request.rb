# frozen_string_literal: true

require "rodauth/oauth"

module Rodauth
  Feature.define(:oauth_pushed_authorization_request, :OauthJwtPushedAuthorizationRequest) do
    depends :oauth_authorize_base

    auth_value_method :oauth_require_pushed_authorization_requests, false
    auth_value_method :oauth_applications_require_pushed_authorization_requests_column, :require_pushed_authorization_requests
    auth_value_method :oauth_pushed_authorization_request_expires_in, 90 # 90 seconds
    auth_value_method :oauth_require_pushed_authorization_request_iss_request_object, true

    auth_value_method :oauth_pushed_authorization_requests_table, :oauth_pushed_requests

    %i[
      oauth_application_id params code expires_in
    ].each do |column|
      auth_value_method :"oauth_pushed_authorization_requests_#{column}_column", column
    end

    # /par
    auth_server_route(:par) do |r|
      require_oauth_application
      before_par_route

      r.post do
        validate_par_params

        ds = db[oauth_pushed_authorization_requests_table]

        code = oauth_unique_id_generator
        push_request_params = {
          oauth_pushed_authorization_requests_oauth_application_id_column => oauth_application[oauth_applications_id_column],
          oauth_pushed_authorization_requests_code_column => code,
          oauth_pushed_authorization_requests_params_column => URI.encode_www_form(request.params),
          oauth_pushed_authorization_requests_expires_in_column => Sequel.date_add(Sequel::CURRENT_TIMESTAMP,
                                                                                   seconds: oauth_pushed_authorization_request_expires_in)
        }

        rescue_from_uniqueness_error do
          ds.insert(push_request_params)
        end

        json_response_success(
          "request_uri" => "urn:ietf:params:oauth:request_uri:#{code}",
          "expires_in" => oauth_pushed_authorization_request_expires_in
        )
      end
    end

    def check_csrf?
      case request.path
      when par_path
        false
      else
        super
      end
    end

    private

    def validate_par_params
      # https://datatracker.ietf.org/doc/html/rfc9126#section-2.1
      # The request_uri authorization request parameter is one exception, and it MUST NOT be provided.
      redirect_response_error("invalid_request") if param_or_nil("request_uri")

      if (request_object = param_or_nil("request")) && features.include?(:oauth_jwt_secured_authorization_request)
        claims = decode_request_object(request_object)

        # https://datatracker.ietf.org/doc/html/rfc9126#section-3-5.3
        # reject the request if the authenticated client_id does not match the client_id claim in the Request Object
        if (client_id = claims["client_id"]) && (client_id != oauth_application[oauth_applications_client_id_column])
          redirect_response_error("invalid_request_object")
        end

        # requiring the iss claim to match the client_id is at the discretion of the authorization server
        if oauth_require_pushed_authorization_request_iss_request_object &&
           (iss = claims.delete("iss")) &&
           iss != oauth_application[oauth_applications_client_id_column]
          redirect_response_error("invalid_request_object")
        end

        if (aud = claims.delete("aud")) && !verify_aud(aud, oauth_jwt_issuer)
          redirect_response_error("invalid_request_object")
        end

        claims.delete("exp")
        request.params.delete("request")

        claims.each do |k, v|
          request.params[k.to_s] = v
        end
      end

      validate_authorize_params
    end

    def validate_authorize_params
      return super unless request.get? && request.path == authorize_path

      if (request_uri = param_or_nil("request_uri"))
        code = request_uri.delete_prefix("urn:ietf:params:oauth:request_uri:")

        table = oauth_pushed_authorization_requests_table
        ds = db[table]

        pushed_request = ds.where(
          oauth_pushed_authorization_requests_oauth_application_id_column => oauth_application[oauth_applications_id_column],
          oauth_pushed_authorization_requests_code_column => code
        ).where(
          Sequel.expr(Sequel[table][oauth_pushed_authorization_requests_expires_in_column]) >= Sequel::CURRENT_TIMESTAMP
        ).first

        redirect_response_error("invalid_request") unless pushed_request

        URI.decode_www_form(pushed_request[oauth_pushed_authorization_requests_params_column]).each do |k, v|
          request.params[k.to_s] = v
        end

        request.params.delete("request_uri")
      elsif oauth_require_pushed_authorization_requests ||
            (oauth_application && oauth_application[oauth_applications_require_pushed_authorization_requests_column])
        redirect_authorize_error("request_uri")
      end
      super
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:require_pushed_authorization_requests] = oauth_require_pushed_authorization_requests
        data[:pushed_authorization_request_endpoint] = par_url
      end
    end
  end
end
