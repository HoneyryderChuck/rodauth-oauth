# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "simplecov" if ENV.key?("CI")

ENV["RAILS_ENV"] = "test"

# for rails integration tests
require_relative "rails_app/config/environment"
require "rails/test_help"

require "fileutils"
require "logger"
require "securerandom"
require "capybara"
require "capybara/dsl"
require "minitest/autorun"
require "minitest/hooks"

require "sequel"
require "roda"
require "rodauth/oauth"
require "rodauth/version"
require "bcrypt"

TEST_SCOPES = %w[user.read user.write].freeze

module OAuthHelpers
  private

  def oauth_application
    @oauth_application ||= begin
      id = DB[:oauth_applications].insert \
        account_id: account[:id],
        name: "Foo",
        description: "this is a foo",
        homepage_url: "https://example.com",
        redirect_uri: "https://example.com/callback",
        client_id: "CLIENT_ID",
        client_secret: "CLIENT_SECRET",
        scopes: TEST_SCOPES.join(",")

      DB[:oauth_applications].filter(id: id).first
    end
  end

  def oauth_grant(params = {})
    @oauth_grant ||= begin
      id = DB[:oauth_grants].insert({
        oauth_application_id: oauth_application[:id],
        account_id: account[:id],
        code: "CODE",
        expires_in: Time.now + 60 * 5,
        redirect_uri: oauth_application[:redirect_uri],
        scopes: oauth_application[:scopes]
      }.merge(params))
      DB[:oauth_grants].filter(id: id).first
    end
  end

  def oauth_token(params = {})
    @oauth_token ||= begin
      id = DB[:oauth_tokens].insert({
        account_id: account[:id],
        oauth_application_id: oauth_application[:id],
        oauth_grant_id: oauth_grant[:id],
        token: "TOKEN",
        refresh_token: "REFRESH_TOKEN",
        expires_in: Time.now + 60 * 5,
        scopes: oauth_grant[:scopes]
      }.merge(params))
      DB[:oauth_tokens].filter(id: id).first
    end
  end

  def account
    @account ||= DB[:accounts].first
  end
end


Dir[File.join(".", "test", "support", "*.rb")].sort.each { |f| require f }
Dir[File.join(".", "test", "support", "**", "*.rb")].sort.each { |f| require f }

