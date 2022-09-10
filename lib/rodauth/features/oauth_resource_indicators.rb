# frozen_string_literal: true

require "rodauth/oauth/version"
require "rodauth/oauth/ttl_store"

module Rodauth
  Feature.define(:oauth_resource_indicators, :OauthResourceIndicators) do
    depends :oauth_authorize_base

    auth_value_method :oauth_grants_resource_column, :resource

    def resource_indicators
      return @resource_indicators if defined?(@resource_indicators)

      resources = param_or_nil("resource")

      return unless resources

      if json_request? || param_or_nil("request") # signed request
        resources = Array(resources)
      else
        query = if request.form_data?
                  request.body.rewind
                  request.body.read
                else
                  request.query_string
                end
        # resource query param does not conform to rack parsing rules
        resources = URI.decode_www_form(query).each_with_object([]) do |(k, v), memo|
          memo << v if k == "resource"
        end
      end

      @resource_indicators = resources
    end

    def require_oauth_authorization(*)
      super

      return unless authorization_token[oauth_grants_resource_column]

      token_indicators = authorization_token[oauth_grants_resource_column]

      token_indicators = token_indicators.split(" ") if token_indicators.is_a?(String)

      authorization_required unless token_indicators.any? { |resource| base_url.start_with?(resource) }
    end

    private

    def validate_token_params
      super

      return unless resource_indicators

      resource_indicators.each do |resource|
        redirect_response_error("invalid_target") unless check_valid_no_fragment_uri?(resource)
      end
    end

    def create_token_from_token(oauth_grant, update_params)
      return super unless resource_indicators

      grant_indicators = oauth_grant[oauth_grants_resource_column]

      grant_indicators = grant_indicators.split(" ") if grant_indicators.is_a?(String)

      redirect_response_error("invalid_target") unless (grant_indicators - resource_indicators) != grant_indicators

      super(oauth_grant, update_params.merge(oauth_grants_resource_column => resource_indicators))
    end

    def check_valid_no_fragment_uri?(uri)
      check_valid_uri?(uri) && URI.parse(uri).fragment.nil?
    end

    module IndicatorAuthorizationCodeGrant
      private

      def validate_authorize_params
        super

        return unless resource_indicators

        resource_indicators.each do |resource|
          redirect_response_error("invalid_target") unless check_valid_no_fragment_uri?(resource)
        end
      end

      def create_token_from_authorization_code(grant_params, *args, oauth_grant: nil)
        return super unless resource_indicators

        oauth_grant ||= valid_locked_oauth_grant(grant_params)

        redirect_response_error("invalid_target") unless oauth_grant[oauth_grants_resource_column]

        grant_indicators = oauth_grant[oauth_grants_resource_column]

        grant_indicators = grant_indicators.split(" ") if grant_indicators.is_a?(String)

        redirect_response_error("invalid_target") unless (grant_indicators - resource_indicators) != grant_indicators

        # update ownership
        if grant_indicators != resource_indicators
          oauth_grant = __update_and_return__(
            db[oauth_grants_table].where(oauth_grants_id_column => oauth_grant[oauth_grants_id_column]),
            oauth_grants_resource_column => resource_indicators
          )
        end

        super({ oauth_grants_id_column => oauth_grant[oauth_grants_id_column] }, *args, oauth_grant: oauth_grant)
      end

      def create_oauth_grant(create_params = {})
        create_params[oauth_grants_resource_column] = resource_indicators.join(" ") if resource_indicators

        super
      end
    end

    module IndicatorIntrospection
      def json_token_introspect_payload(grant)
        return super unless grant[oauth_grants_id_column]

        payload = super

        token_indicators = grant[oauth_grants_resource_column]

        token_indicators = token_indicators.split(" ") if token_indicators.is_a?(String)

        payload[:aud] = token_indicators

        payload
      end

      def introspection_request(*)
        payload = super

        payload[oauth_grants_resource_column] = payload["aud"] if payload["aud"]

        payload
      end
    end

    module IndicatorJwt
      def jwt_claims(*)
        return super unless resource_indicators

        super.merge(aud: resource_indicators)
      end

      def jwt_decode(token, verify_aud: true, **args)
        claims = super(token, verify_aud: false, **args)

        return claims unless verify_aud

        return unless claims["aud"] && claims["aud"].one? { |aud| request.url.starts_with?(aud) }

        claims
      end
    end

    def self.included(rodauth)
      super
      rodauth.send(:include, IndicatorAuthorizationCodeGrant) if rodauth.features.include?(:oauth_authorization_code_grant)
      rodauth.send(:include, IndicatorIntrospection) if rodauth.features.include?(:oauth_token_introspection)
      rodauth.send(:include, IndicatorJwt) if rodauth.features.include?(:oauth_jwt)
    end
  end
end
