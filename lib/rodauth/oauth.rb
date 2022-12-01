# frozen_string_literal: true

require "rodauth"
require "rodauth/oauth/version"

module Rodauth
  module OAuth
    module FeatureExtensions
      def auth_server_route(*args, &blk)
        routes = route(*args, &blk)

        handle_meth = routes.last

        define_method(:"#{handle_meth}_for_auth_server") do
          next unless is_authorization_server?

          send(:"#{handle_meth}_not_for_auth_server")
        end

        alias_method :"#{handle_meth}_not_for_auth_server", handle_meth
        alias_method handle_meth, :"#{handle_meth}_for_auth_server"
      end

      # override
      def translatable_method(meth, value)
        define_method(meth) { |*args| translate(meth, value, *args) }
        auth_value_methods(meth)
      end
    end
  end

  Feature.prepend OAuth::FeatureExtensions
end

require "rodauth/oauth/railtie" if defined?(Rails)
