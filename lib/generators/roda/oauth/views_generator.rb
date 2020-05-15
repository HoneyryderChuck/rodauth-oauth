# frozen_string_literal: true

require "rails/generators/base"

module Rodauth
  module OAuth
    module Rails
      module Generators
        class ViewsGenerator < ::Rails::Generators::Base
          source_root "#{__dir__}/templates"
          namespace "roda:oauth:views"

          DEFAULT = %w[oauth_authorize]
          VIEWS = {
            oauth_authorize: DEFAULT,
            oauth_applications: %w[oauth_applications oauth_application new_oauth_application]
          }

          DEPENDENCIES = {
            active_sessions: :logout,
            otp:             :two_factor_base,
            sms_codes:       :two_factor_base,
            recovery_codes:  :two_factor_base,
            webauthn:        :two_factor_base,
          }

          class_option :features, type: :array,
            desc: "Roda OAuth features to generate views for (oauth_applications etc.)",
            default: DEFAULT

          class_option :all, aliases: "-a", type: :boolean,
            desc: "Generates views for all Roda OAuth features",
            default: false

          class_option :directory, aliases: "-d", type: :string,
            desc: "The directory under app/views/* into which to create views",
            default: "rodauth"

          def create_views
            features = options[:all] ? VIEWS.keys : (DEFAULT+options[:features]).map(&:to_sym)

            views = features.inject([]) do |list, feature|
              list |= VIEWS[feature] || []
              list |= VIEWS[DEPENDENCIES[feature]] || []
            end

            views.each do |view|
              template "app/views/rodauth/#{view}.html.erb",
                "app/views/#{options[:directory].underscore}/#{view}.html.erb"
            end
          end
        end
      end
    end
  end
end
