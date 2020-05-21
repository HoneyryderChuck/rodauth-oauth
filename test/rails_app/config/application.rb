# frozen_string_literal: true

require_relative "boot"

require "active_record/railtie"
require "action_controller/railtie"
require "action_mailer/railtie"
require "active_job/railtie"
require "rails/test_unit/railtie"

require "rodauth/rails"

module RailsApp
  class Application < Rails::Application
    config.root = Pathname("#{__dir__}/..").expand_path
    config.logger = Logger.new(ENV.key?("RODAUTH_DEBUG") ? $stderr : nil)
    config.eager_load = true
    config.action_dispatch.show_exceptions = false
    config.action_mailer.delivery_method = :test
    config.autoload_paths += %W[#{config.root}/lib]
    config.active_record.maintain_test_schema = false
    config.action_controller.allow_forgery_protection = false
  end
end
