# frozen_string_literal: true

module Rodauth
  Feature.define(:oauth_device_grant, :OauthDeviceGrant) do
    depends :oauth_base

    auth_value_method :use_oauth_device_code_grant_type?, false

    before "device_authorization"
    before "device_verification"

    notice_flash "The device is verified", "device_verification"
    error_flash "No device to authorize with the given user code", "user_code_not_found"

    view "device_verification", "Device Verification", "device_verification"
    view "device_search", "Device Search", "device_search"

    button "Verify", "oauth_device_verification"
    button "Search", "oauth_device_search"

    translatable_method :invalid_grant_type_message, "Invalid grant type"
    translatable_method :expired_token_message, "the device code has expired"
    translatable_method :access_denied_message, "the authorization request has been denied"
    translatable_method :authorization_pending_message, "the authorization request is still pending"
    translatable_method :slow_down_message, "authorization request is still pending but poll interval should be increased"

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
    route(:device_authorization) do |r|
      next unless is_authorization_server? && use_oauth_device_code_grant_type?

      before_device_authorization_route

      r.post do
        require_oauth_application

        user_code = generate_user_code
        device_code = transaction do
          before_device_authorization
          create_oauth_grant(oauth_grants_user_code_column => user_code)
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
    route(:device) do |r|
      next unless is_authorization_server? && use_oauth_device_code_grant_type?

      before_device_route
      require_authorizable_account

      r.get do
        if (user_code = param_or_nil("user_code"))
          oauth_grant = db[oauth_grants_table].where(
            oauth_grants_user_code_column => user_code,
            oauth_grants_revoked_at_column => nil
          ).where(Sequel[oauth_grants_expires_in_column] >= Sequel::CURRENT_TIMESTAMP).first

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
          unless param_or_nil("user_code")
            set_redirect_error_flash invalid_grant_message
            redirect device_path
          end

          transaction do
            before_device_verification
            create_oauth_token("device_code")
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

    private

    def generate_user_code
      user_code_size = oauth_device_code_grant_user_code_size
      SecureRandom.random_number(36**user_code_size)
                  .to_s(36) # 0 to 9, a to z
                  .upcase
                  .rjust(user_code_size, "0")
    end

    def authorized_oauth_application?(oauth_application, client_secret)
      # skip if using device grant
      #
      # requests may be performed by devices with no knowledge of client secret.
      return true if !client_secret && oauth_application && use_oauth_device_code_grant_type?

      super
    end

    def create_oauth_token(grant_type)
      case grant_type
      when "urn:ietf:params:oauth:grant-type:device_code"
        throw_json_response_error(invalid_oauth_response_status, "invalid_grant_type") unless use_oauth_device_code_grant_type?

        oauth_grant = db[oauth_grants_table].where(
          oauth_grants_code_column => param("device_code"),
          oauth_grants_oauth_application_id_column => oauth_application[oauth_applications_id_column]
        ).for_update.first

        throw_json_response_error(invalid_oauth_response_status, "invalid_grant") unless oauth_grant

        now = Time.now

        if oauth_grant[oauth_grants_revoked_at_column]
          oauth_token = db[oauth_tokens_table]
                        .where(Sequel[oauth_tokens_table][oauth_tokens_expires_in_column] >= Sequel::CURRENT_TIMESTAMP)
                        .where(Sequel[oauth_tokens_table][oauth_tokens_revoked_at_column] => nil)
                        .where(oauth_tokens_oauth_grant_id_column => oauth_grant[oauth_grants_id_column])
                        .first

          throw_json_response_error(invalid_oauth_response_status, "access_denied") unless oauth_token
        elsif oauth_grant[oauth_grants_expires_in_column] < now
          throw_json_response_error(invalid_oauth_response_status, "expired_token")
        else
          last_polled_at = oauth_grant[oauth_grants_last_polled_at_column]
          if last_polled_at && convert_timestamp(last_polled_at) + oauth_device_code_grant_polling_interval > now
            throw_json_response_error(invalid_oauth_response_status, "slow_down")
          else
            db[oauth_grants_table].where(oauth_grants_id_column => oauth_grant[oauth_grants_id_column])
                                  .update(oauth_grants_last_polled_at_column => Sequel::CURRENT_TIMESTAMP)
            throw_json_response_error(invalid_oauth_response_status, "authorization_pending")
          end
        end
        oauth_token
      when "device_code"
        redirect_response_error("invalid_grant_type") unless use_oauth_device_code_grant_type?

        # fetch oauth grant
        oauth_grant = db[oauth_grants_table].where(
          oauth_grants_user_code_column => param("user_code"),
          oauth_grants_revoked_at_column => nil
        ).where(Sequel[oauth_grants_expires_in_column] >= Sequel::CURRENT_TIMESTAMP)
                                            .for_update
                                            .first

        return unless oauth_grant

        # update ownership
        db[oauth_grants_table].where(oauth_grants_id_column => oauth_grant[oauth_grants_id_column])
                              .update(
                                oauth_grants_user_code_column => nil,
                                oauth_grants_account_id_column => account_id
                              )

        create_params = {
          oauth_tokens_account_id_column => account_id,
          oauth_tokens_oauth_application_id_column => oauth_grant[oauth_grants_oauth_application_id_column],
          oauth_tokens_oauth_grant_id_column => oauth_grant[oauth_grants_id_column],
          oauth_tokens_scopes_column => oauth_grant[oauth_grants_scopes_column]
        }
        create_oauth_token_from_authorization_code(oauth_grant, create_params)
      else
        super
      end
    end

    def validate_oauth_token_params
      grant_type = param_or_nil("grant_type")

      if grant_type == "urn:ietf:params:oauth:grant-type:device_code" && !param_or_nil("device_code")
        redirect_response_error("invalid_request")
      end
      super
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        if use_oauth_device_code_grant_type?
          data[:grant_types_supported] << "urn:ietf:params:oauth:grant-type:device_code"
          data[:device_authorization_endpoint] = device_authorization_url
        end
      end
    end
  end
end
