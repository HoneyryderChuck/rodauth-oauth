# frozen_string_literal: true

require "rodauth/oauth"

module Rodauth
  Feature.define(:oauth_client_id_metadata_document, :OauthClientIdMetadataDocument) do
    depends :oauth_authorize_base

    DOT_SEGMENTS = %w[. ..].freeze

    FORBIDDEN_TOKEN_AUTH_METHODS = %w[client_secret_post client_secret_basic client_secret_jwt].freeze

    def oauth_application
      super || begin
        client_id = param_or_nil("client_id")

        return unless client_id && valid_cimd_url?(client_id)

        return if @client_id_lookup

        @client_id_lookup = true

        client_metadata = http_request_with_cache(client_id)

        # 4.1 The client metadata document MUST contain a client_id property whose value MUST match the URL of the document
        redirect_response_error("invalid_request") unless client_metadata[:client_id] == client_id

        validate_client_metadata_document(client_metadata)

        @client_id_lookup = false

        # rewrite metadata params into column names
        create_params = client_metadata.to_h do |k, v|
          k = case k
              when :redirect_uris
                v = v.join(" ")
                :redirect_uri
              when :client_uri
                :homepage_url
              when :grant_types, :response_types, :contacts
                v = v.join(" ")
                k
              when :client_name
                :name
              when :scope
                :scopes
              else
                k
              end
          [send(:"oauth_applications_#{k}_column"), v]
        end

        applications_ds = db[oauth_applications_table]
        application_columns = applications_ds.columns

        create_params.delete_if { |k, _| !application_columns.include?(k) }
        @oauth_application = __insert_or_do_nothing_and_return__(
          applications_ds,
          oauth_applications_id_column,
          [oauth_applications_client_id_column],
          create_params
        )
      end
    end

    private

    def valid_cimd_url?(client_id)
      return false unless URI::DEFAULT_PARSER.make_regexp("https").match?(client_id)

      uri = URI(client_id)
      # Client identifier URLs MUST have an "https" scheme,
      return false unless uri.scheme == "https"

      path = uri.path
      # MUST contain a path component
      return false if path.empty? ||
                      # MUST NOT contain single-dot or double-dot path segments
                      path.split("/").any? { |seg| DOT_SEGMENTS.include?(seg) }

      return false unless
        # MUST NOT contain a fragment component
        (uri.fragment.nil? || uri.fragment.empty?) &&
        # MUST NOT contain a username or password Client identifier URLs
        (uri.userinfo.nil? || uri.userinfo.empty?) &&
        # SHOULD NOT include a query string component, and MAY contain a port.
        (uri.query.nil? || uri.query.empty?)

      true
    end

    def validate_client_metadata_document(metadata)
      if (token_endpoint_auth_method = metadata[:token_endpoint_auth_method]) &&
         FORBIDDEN_TOKEN_AUTH_METHODS.include?(token_endpoint_auth_method)
        # the token_endpoint_auth_method property MUST NOT include client_secret_post, client_secret_basic, client_secret_jwt,
        # or any other method based around a shared symmetric secret
        redirect_response_error("invalid_request")
      end

      # the client_secret and client_secret_expires_at properties MUST NOT be used
      redirect_response_error("invalid_request") if metadata.key?(:client_secret) || metadata.key?(:client_secret_expires_at)
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:client_id_metadata_document_supported] = true
      end
    end
  end
end
