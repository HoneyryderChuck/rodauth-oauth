# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

if ENV.key?("CI")
  require "simplecov"
  commands = [RUBY_ENGINE, RUBY_VERSION, ENV["DATABASE_URL"][%r{(\w+):(//|:)}, 1], ENV["JWT_LIB"], ENV["BUNDLE_GEMFILE"]].compact
  SimpleCov.command_name commands.join("-")
  SimpleCov.coverage_dir "coverage/#{RUBY_ENGINE}-#{RUBY_VERSION}"
end

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

PKCE_VERIFIER = "VERIFIER"
PKCE_CHALLENGE = "a1Y-Z7sHPycP84FUZMgqhDyqVo6DdP5EUEXrLaTUge0" # using S256

module OAuthHelpers
  attr_reader :app

  private

  def app=(app)
    @app = Capybara.app = app
  end

  def test_scopes
    %w[user.read user.write]
  end

  def oauth_application(params = {})
    @oauth_application ||= set_oauth_application(params)
  end

  def set_oauth_application(params)
    id = db[:oauth_applications].insert({
      account_id: account[:id],
      name: "Foo",
      description: "this is a foo",
      homepage_url: "https://example.com",
      redirect_uri: "https://example.com/callback",
      client_id: "CLIENT_ID",
      client_secret: generate_client_secret("CLIENT_SECRET"),
      scopes: test_scopes.join(" ")
    }.merge(params))
    db[:oauth_applications].filter(id: id).first
  end

  def oauth_grant(params = {})
    @oauth_grant ||= set_oauth_grant(params)
  end

  def set_oauth_grant(params = {})
    application = params.delete(:oauth_application) || oauth_application
    id = db[:oauth_grants].insert({
      oauth_application_id: application[:id],
      account_id: account[:id],
      type: default_grant_type,
      code: "CODE",
      expires_in: Sequel.date_add(Sequel::CURRENT_TIMESTAMP, seconds: 60 * 5),
      redirect_uri: application[:redirect_uri],
      scopes: application[:scopes]
    }.merge(params))
    db[:oauth_grants].filter(id: id).first
  end

  def oauth_grant_with_token(params = {})
    @oauth_grant_with_token ||= set_oauth_grant_with_token(params)
  end

  def set_oauth_grant_with_token(params = {})
    set_oauth_grant({
      token: "TOKEN",
      refresh_token: "REFRESH_TOKEN",
      code: nil
    }.merge(params))
  end

  def account
    @account ||= db[:accounts].first
  end

  def authorization_header(opts = {})
    ["#{opts.delete(:username) || 'foo@example.com'}:#{opts.delete(:password) || '0123456789'}"].pack("m*")
  end

  def json_body
    @json_body ||= JSON.parse(last_response.body)
  end

  def generate_client_secret(secret)
    BCrypt::Password.create(secret, cost: BCrypt::Engine::MIN_COST)
  end
end

# requiring the rails integration first, because certain variables need to be loaded upfront
# before the minitest has to a chance to parallelize, specifically: we don't want to parallelize
# tests when running sqlite (the db adapter isn't playing well with multi-threading).
#
require_relative "support/rails_integration"

Dir[File.join(".", "test", "support", "*.rb")].sort.each { |f| require f }
Dir[File.join(".", "test", "support", "**", "*.rb")].sort.each { |f| require f }
Dir[File.join(".", "lib", "rodauth", "features", "**", "*.rb")].sort.each { |f| require f } if defined?(RBS)
