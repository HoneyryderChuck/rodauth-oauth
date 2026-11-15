# frozen_string_literal: true

require "ipaddr"
require "rodauth/oauth"

module Rodauth
  Feature.define(:oauth_client_id_metadata_document, :OauthClientIdMetadataDocument) do
    depends :oauth_authorize_base

    DOT_SEGMENTS = %w[. ..].freeze

    FORBIDDEN_TOKEN_AUTH_METHODS = %w[client_secret_post client_secret_basic client_secret_jwt].freeze

    # https://github.com/arkadiyt/ssrf_filter/blob/main/lib/ssrf_filter/ssrf_filter.rb#L40
    # https://en.wikipedia.org/wiki/Reserved_IP_addresses
    IPV4_BLACKLIST = [
      ::IPAddr.new('0.0.0.0/8'), # Current network (only valid as source address)
      ::IPAddr.new('10.0.0.0/8'), # Private network
      ::IPAddr.new('100.64.0.0/10'), # Shared Address Space
      ::IPAddr.new('127.0.0.0/8'), # Loopback
      ::IPAddr.new('169.254.0.0/16'), # Link-local
      ::IPAddr.new('172.16.0.0/12'), # Private network
      ::IPAddr.new('192.0.0.0/24'), # IETF Protocol Assignments
      ::IPAddr.new('192.0.2.0/24'), # TEST-NET-1, documentation and examples
      ::IPAddr.new('192.168.0.0/16'), # Private network
      ::IPAddr.new('198.18.0.0/15'), # Network benchmark tests
      ::IPAddr.new('198.51.100.0/24'), # TEST-NET-2, documentation and examples
      ::IPAddr.new('203.0.113.0/24'), # TEST-NET-3, documentation and examples
      ::IPAddr.new('224.0.0.0/4'), # IP multicast (former Class D network)
      ::IPAddr.new('240.0.0.0/4'), # Reserved (former Class E network)
      ::IPAddr.new('255.255.255.255') # Broadcast
    ].freeze

    # NAT64 local-use prefix (RFC 8215), uses RFC 6052 /48 encoding (checked at runtime).
    NAT64_LOCAL_PREFIX = ::IPAddr.new('64:ff9b:1::/48').freeze

    IPV6_BLACKLIST = ([
      ::IPAddr.new('::/128'), # Unspecified address
      ::IPAddr.new('::1/128'), # Loopback
      ::IPAddr.new('100::/64'), # Discard prefix (RFC 6666)
      ::IPAddr.new('100:0:0:1::/64'), # Dummy IPv6 prefix (RFC 9780)
      ::IPAddr.new('2001::/32'), # Teredo tunneling
      ::IPAddr.new('2001:2::/48'), # Benchmarking (RFC 5180)
      ::IPAddr.new('2001:10::/28'), # Deprecated (previously ORCHID)
      ::IPAddr.new('2001:20::/28'), # ORCHIDv2
      ::IPAddr.new('2001:db8::/32'), # Addresses used in documentation and example source code
      ::IPAddr.new('2002::/16'), # 6to4
      ::IPAddr.new('3fff::/20'), # Documentation (RFC 9637)
      ::IPAddr.new('5f00::/16'), # Segment Routing (SRv6) SIDs (RFC 9602)
      ::IPAddr.new('fc00::/7'), # Unique local address
      ::IPAddr.new('fe80::/10'), # Link-local address
      ::IPAddr.new('ff00::/8') # Multicast
    ] + IPV4_BLACKLIST.flat_map do |ipaddr|
      prefixlen = prefixlen_from_ipaddr(ipaddr)

      # Don't call ipaddr.ipv4_compat because it prints out a deprecation warning on ruby 2.5+
      ipv4_compatible  = IPAddr.new(ipaddr.to_i, Socket::AF_INET6).mask(96 + prefixlen)
      ipv4_mapped      = ipaddr.ipv4_mapped.mask(96 + prefixlen)
      # IPv4-translated (RFC 2765): ::ffff:0:x.x.x.x/96+n
      ipv4_translated  = IPAddr.new("::ffff:0:#{ipaddr}").mask(96 + prefixlen)
      # NAT64 well-known prefix (RFC 6052): 64:ff9b::x.x.x.x/96+n
      nat64_well_known = IPAddr.new("64:ff9b::#{ipaddr}").mask(96 + prefixlen)

      [ipv4_compatible, ipv4_mapped, ipv4_translated, nat64_well_known]
    end).freeze

    auth_value_method :oauth_applications_created_via_client_id_metadata_column, nil

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

        create_params = client_metadata_document_to_oauth_application_params(client_metadata)

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

      # Authorization servers MUST NOT fetch a Client ID Metadata
      # Document URL or any URLs contained within a Client ID Metadata
      # Document that resolve to special-use IP addresses as defined in
      # [RFC6890].
      return false unless valid_ip?(uri)
      true
    end

    def valid_ip?(uri)
      ip = IPAddr.new(IPSocket.getaddress(uri.host))

      # reject IP masks
      ip_range = ipaddr.to_range
      return false ip_range.first != ip_range.last

      if ip.ipv4?
        return false if IPV4_BLACKLIST.any? { |range| range.include?(ip) }
      else
        return false if IPV6_BLACKLIST.any? { |range| range.include?(ip) }
      end

      return true
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

      # A client SHOULD use the token_endpoint_auth_methods_supported
      # ([OpenID.RPMetadataChoices]) property to advertise which client
      # authentication methods the client supports, even if the value is only
      # ["none"].
      return unless (supported_auth_methods = metadata.delete(:token_endpoint_auth_methods_supported))

      supported_auth_methods &= oauth_token_endpoint_auth_methods_supported
      redirect_response_error("invalid_request") if supported_auth_methods.empty?
      supported_auth_methods.shift if supported_auth_methods.first == "none" && supported_auth_methods.size > 1
      metadata[:token_endpoint_auth_method] = supported_auth_methods.first
    end

    # rewrite metadata params into column names
    def client_metadata_document_to_oauth_application_params(client_metadata)
      params = Hash[
          client_metadata.map do |k, v|
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
        ]

      params[oauth_applications_created_via_client_id_metadata_column] = true if oauth_applications_created_via_client_id_metadata_column

      params
    end

    def oauth_server_metadata_body(*)
      super.tap do |data|
        data[:client_id_metadata_document_supported] = true
      end
    end
  end
end
