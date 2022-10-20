# frozen_string_literal: true

require "rodauth/oauth"

module Rodauth
  Feature.define(:oauth_device_code_grant, :OauthDeviceCodeGrant) do
    depends :oauth_authorize_base

    before "device_authorization"
    before "device_verification"

    notice_flash "The device is verified", "device_verification"
    error_flash "No device to authorize with the given user code", "user_code_not_found"

    view "device_verification", "Device Verification", "device_verification"
    view "device_search", "Device Search", "device_search"

    button "Verify", "oauth_device_verification"
    button "Search", "oauth_device_search"

    auth_value_method :oauth_grants_user_code_column, :user_code
    auth_value_method :oauth_grants_last_polled_at_column, :last_polled_at

    translatable_method :oauth_device_search_page_lead, "Insert the user code from the device you'd like to authorize."
    translatable_method :oauth_device_verification_page_lead, "The device with user code %<user_code>s would like to access your data."
    translatable_method :oauth_expired_token_message, "the device code has expired"
    translatable_method :oauth_access_denied_message, "the authorization request has been denied"
    translatable_method :oauth_authorization_pending_message, "the authorization request is still pending"
    translatable_method :oauth_slow_down_message, "authorization request is still pending but poll interval should be increased"

    auth_value_method :oauth_device_code_grant_polling_interval, 5 # seconds
    auth_value_method :oauth_device_code_grant_user_code_size, 8 # characters
    %w[user_code].each do |param|
      auth_value_method :"oauth_grant_#{param}_param", param
    end
    translatable_method :oauth_grant_user_code_label, "User code"

    auth_value_methods(
      :generate_user_code
    )

    # /device-authorization
    auth_server_route(:device_authorization) do |r|
      before_device_authorization_route

      r.post do
        require_oauth_application

        user_code = generate_user_code
        device_code = transaction do
          before_device_authorization
          create_oauth_grant(
            oauth_grants_type_column => "device_code",
            oauth_grants_user_code_column => user_code
          )
        end

        json_response_success \
          "device_code" => device_code,
          "user_code" => user_code,
          "verification_uri" => device_url,
          "verification_uri_complete" => device_url(user_code: user_code),
          "expires_in" => oauth_grant_expires_in,
          "interval" => oauth_device_code_grant_polling_interval
      end
    end

    # /device
    auth_server_route(:device) do |r|
      before_device_route
      require_authorizable_account

      r.get do
        if (user_code = param_or_nil("user_code"))
          oauth_grant = valid_oauth_grant_ds(oauth_grants_user_code_column => user_code).first

          unless oauth_grant
            set_redirect_error_flash user_code_not_found_error_flash
            redirect device_path
          end

          scope.instance_variable_set(:@oauth_grant, oauth_grant)
          device_verification_view
        else
          device_search_view
        end
      end

      r.post do
        catch_error do
          unless (user_code = param_or_nil("user_code")) && !user_code.empty?
            set_redirect_error_flash oauth_invalid_grant_message
            redirect device_path
          end

          transaction do
            before_device_verification
            create_token("device_code")
          end
        end
        set_notice_flash device_verification_notice_flash
        redirect device_path
      end
    end

    def check_csrf?
      case request.path
      when device_authorization_path
        false
      else
        super
      end
    end

    def oauth_grant_types_supported
      super | %w[urn:ietf:params:oauth:grant-type:device_code]
    end

    private

    def generate_user_code
      user_code_size = oauth_device_code_grant_user_code_size
      SecureRandom.random_number(36**user_code_size)
                  .to_s(36) # 0 to 9, a to z
                  .upcase
                  .rjust(user_code_size, "0")
    end

    # TODO: think about removing this and recommend PKCE
    def supports_auth_method?(oauth_application, auth_method)
      return super unless auth_method == "none"

      request.path == device_authorization_path || request.params.key?("device_code") || super
    end

    def create_token(grant_type)
      if supported_grant_type?(grant_type, "urn:ietf:params:oauth:grant-type:device_code")

        oauth_grant = db[oauth_grants_table].where(
          oauth_grants_type_column => "device_code",
          oauth_grants_code_column => param("device_code"),
          oauth_grants_oauth_application_id_column => oauth_application[oauth_applications_id_column]
        ).for_update.first

        throw_json_response_error(oauth_invalid_response_status, "invalid_grant") unless oauth_grant

        now = Time.now

        if oauth_grant[oauth_grants_user_code_column].nil?
          return create_token_from_authorization_code(
            { oauth_grants_id_column => oauth_grant[oauth_grants_id_column] },
            oauth_grant: oauth_grant
          )
        end

        if oauth_grant[oauth_grants_revoked_at_column]
          throw_json_response_error(oauth_invalid_response_status, "access_denied")
        elsif oauth_grant[oauth_grants_expires_in_column] < now
          throw_json_response_error(oauth_invalid_response_status, "expired_token")
        else
          last_polled_at = oauth_grant[oauth_grants_last_polled_at_column]
          if last_polled_at && convert_timestamp(last_polled_at) + oauth_device_code_grant_polling_interval > now
            throw_json_response_error(oauth_invalid_response_status, "slow_down")
          else
            db[oauth_grants_table].where(oauth_grants_id_column => oauth_grant[oauth_grants_id_column])
                                  .update(oauth_grants_last_polled_at_column => Sequel::CURRENT_TIMESTAMP)
            throw_json_response_error(oauth_invalid_response_status, "authorization_pending")
          end
        end
      elsif grant_type == "device_code"

        # fetch oauth grant
        rs = valid_oauth_grant_ds(
          oauth_grants_user_code_column => param("user_code")
        ).update(oauth_grants_user_code_column => nil, oauth_grants_type_column => "device_code")

        return unless rs.positive?
      else
        super
      end
    end

    def validate_token_params
      grant_type = param_or_nil("grant_type")

      if grant_type == "urn:ietf:params:oauth:grant-type:device_code" && !param_or_nil("device_code")
        redirect_response_error("invalid_request")
      end
      super
    end

    def store_token(grant_params, update_params = {})
      return super unless grant_params[oauth_grants_user_code_column]

      # do not clean up device code just yet
      update_params.delete(oauth_grants_code_column)

      update_params[oauth_grants_user_code_column] = nil
      update_params[oauth_grants_account_id_column] = account_id

      super(grant_params, update_params)
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:device_authorization_endpoint] = device_authorization_url
      end
    end
  end
end
