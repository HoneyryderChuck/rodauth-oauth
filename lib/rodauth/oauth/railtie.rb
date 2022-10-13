# frozen_string_literal: true

module Rodauth
  module OAuth
    module ControllerMethods
      def self.included(controller)
        # ActionController::API doesn't have helper methods
        controller.helper_method :current_oauth_account, :current_oauth_application if controller.respond_to?(:helper_method)
      end

      def current_oauth_account(name = nil)
        rodauth(name).current_oauth_account
      end

      def current_oauth_application(name = nil)
        rodauth(name).current_oauth_application
      end
    end

    class Railtie < ::Rails::Railtie
      initializer "rodauth.controller" do
        ActiveSupport.on_load(:action_controller) do
          include ControllerMethods
        end
      end
    end
  end
end
