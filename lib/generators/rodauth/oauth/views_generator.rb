# frozen_string_literal: true

require "rails/generators"

module Rodauth::OAuth
  module Rails
    module Generators
      class ViewsGenerator < ::Rails::Generators::Base
        source_root "#{__dir__}/templates"
        namespace "rodauth:oauth:views"
        desc "Generate db migrations for rodauth-oauth in your application."

        DEFAULT = %w[authorize].freeze
        VIEWS = {
          oauth_authorize: DEFAULT,
          oauth_applications: %w[oauth_applications oauth_application new_oauth_application]
        }.freeze

        DEPENDENCIES = {
        }.freeze

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
          features = options[:all] ? VIEWS.keys : (%i[oauth_authorize] + options[:features]).map(&:to_sym).uniq

          views = features.inject([]) do |list, feature|
            list |= VIEWS[feature] || []
            list |= VIEWS[DEPENDENCIES[feature]] || []
          end

          directory = options[:directory].underscore
          views.each do |view|
            copy_file "app/views/rodauth/#{view}.html.erb",
                     "app/views/#{directory}/#{view}.html.erb" do |content|
              content = content.gsub("rodauth/", "#{directory}/")
              content
            end
          end
        end
      end
    end
  end
end
