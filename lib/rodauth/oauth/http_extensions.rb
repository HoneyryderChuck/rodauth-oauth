# frozen_string_literal: true

require "uri"
require "net/http"
require "rodauth/oauth/ttl_store"

module Rodauth
  module OAuth
    module HTTPExtensions
      REQUEST_CACHE = OAuth::TtlStore.new

      private

      def http_request(uri, form_data = nil)
        uri = URI(uri)

        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == "https"

        if form_data
          request = Net::HTTP::Post.new(uri.request_uri)
          request["content-type"] = "application/x-www-form-urlencoded"
          request.set_form_data(form_data)
        else
          request = Net::HTTP::Get.new(uri.request_uri)
        end
        request["accept"] = json_response_content_type

        yield request if block_given?

        response = http.request(request)
        authorization_required unless response.code.to_i == 200
        response
      end

      def http_request_with_cache(uri, *args)
        uri = URI(uri)

        response = http_request_cache[uri]

        return response if response

        http_request_cache.set(uri) do
          response = http_request(uri, *args)
          ttl = if response.key?("cache-control")
                  cache_control = response["cache-control"]
                  cache_control[/max-age=(\d+)/, 1].to_i
                elsif response.key?("expires")
                  Time.parse(response["expires"]).to_i - Time.now.to_i
                end

          [JSON.parse(response.body, symbolize_names: true), ttl]
        end
      end

      def http_request_cache
        REQUEST_CACHE
      end
    end
  end
end
