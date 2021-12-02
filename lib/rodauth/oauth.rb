# frozen_string_literal: true

require "rodauth"

require "rodauth/oauth/version"

require "rodauth/oauth/railtie" if defined?(Rails)

Rodauth::I18n.directories << File.expand_path(File.join(__dir__, "..", "..", "locales")) if defined?(Rodauth::I18n)
