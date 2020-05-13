# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "fileutils"
require "logger"
require "securerandom"
require "capybara"
require "capybara/dsl"
require "minitest/autorun"
require "minitest/hooks"

require "sequel"
require "roda"
require "rodauth"
require "bcrypt"

db_path = File.join(Dir.tmpdir, "roda-oauth.db")
FileUtils.rm(db_path, force: true)

DB = Sequel.sqlite(db_path)
DB.loggers << Logger.new($stderr) if ENV.key?("RODAUTH_DEBUG")

Sequel.extension :migration
require "rodauth/migrations"
Sequel::Migrator.run(DB, "test/migrate")

Base = Class.new(Roda)
Base.opts[:check_dynamic_arity] = Base.opts[:check_arity] = :warn
Base.plugin :flash
Base.plugin :render, views: "test/views", layout_opts: { path: "test/views/layout.str" }
Base.plugin(:not_found) { raise "path #{request.path_info} not found" }
Base.plugin :common_logger if ENV.key?("RODAUTH_DEBUG")

require "roda/session_middleware"
Base.opts[:sessions_convert_symbols] = true
Base.use RodaSessionMiddleware, secret: SecureRandom.random_bytes(64), key: "rack.session"

class RodauthTest < Minitest::Test
  include Minitest::Hooks
  include Capybara::DSL

  attr_reader :app

  def app=(app)
    @app = Capybara.app = app
  end

  def rodauth(&block)
    @rodauth_block = block
  end

  def rodauth_opts(type = {})
    opts = type.is_a?(Hash) ? type : {}
    opts[:csrf] = :route_csrf
    opts
  end

  def roda(type = nil, &block)
    jwt_only = type == :jwt

    app = Class.new(Base)
    app.opts[:unsupported_block_result] = :raise
    app.opts[:unsupported_matcher] = :raise
    app.opts[:verbatim_string_matcher] = true
    rodauth_block = @rodauth_block
    opts = rodauth_opts(type)

    opts[:json] = jwt_only ? :only : true

    app.plugin(:rodauth, opts) do
      instance_exec(&rodauth_block)
    end
    app.route(&block)
    app.precompile_rodauth_templates unless @no_precompile
    self.app = app
  end

  def setup_application
    rodauth do
      enable :http_basic_auth, :oauth
      oauth_application_default_scope "user.read"
      oauth_application_scopes %w[user.read user.write]
      password_match? do |_password|
        true
      end
    end
    roda do |r|
      r.rodauth

      r.on "callback" do
        "Callback"
      end

      r.root do
        flash["error"] || flash["notice"] || "Unauthorized"
      end

      rodauth.require_authentication
      yield(rodauth) if block_given?
      rodauth.require_oauth_authorization

      r.on "private" do
        r.get do
          flash["error"] || flash["notice"] || "Authorized"
        end
      end
    end
  end

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
        scopes: %w[user.read]

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

  def login(opts = {})
    visit(opts[:path] || "/login") unless opts[:visit] == false
    fill_in "Login", with: opts.fetch(:login, "foo@example.com")
    fill_in "Password", with: opts.fetch(:pass, "0123456789")
    click_button "Login"
  end

  def authorization_header(opts = {})
    ["#{opts.delete(:username) || 'foo@example.com'}:#{opts.delete(:password) || '0123456789'}"].pack("m*")
  end

  def around
    DB.transaction(rollback: :always, savepoint: true, auto_savepoint: true) { super }
  end

  def around_all
    DB.transaction(rollback: :always) do
      hash = BCrypt::Password.create("0123456789", cost: BCrypt::Engine::MIN_COST)
      DB[:accounts].insert(email: "foo@example.com", status_id: 2, ph: hash)
      super
    end
  end

  def teardown
    Capybara.reset_sessions!
    Capybara.use_default_driver
  end
end
