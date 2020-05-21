# frozen_string_literal: true

RODADB = begin
  db = if RUBY_ENGINE == "jruby"
         Sequel.connect("jdbc:sqlite::memory:")
       else
         Sequel.connect("sqlite::memory:")
       end
  db.loggers << Logger.new($stderr) if ENV.key?("RODAUTH_DEBUG")
  Sequel.extension :migration
  require "rodauth/migrations"
  Sequel::Migrator.run(db, "test/migrate")
  db
end


Base = Class.new(Roda)
Base.opts[:check_dynamic_arity] = Base.opts[:check_arity] = :warn
Base.plugin :flash
Base.plugin :render, views: "test/views", layout_opts: { path: "test/views/layout.str" }
Base.plugin(:not_found) { raise "path #{request.path_info} not found" }
Base.plugin :common_logger if ENV.key?("RODAUTH_DEBUG")

require "roda/session_middleware"
Base.opts[:sessions_convert_symbols] = true
Base.use RodaSessionMiddleware, secret: SecureRandom.random_bytes(64), key: "rack.session"

class RodaIntegration < Minitest::Test
  include OAuthHelpers
  include Minitest::Hooks
  include Capybara::DSL

  attr_reader :app

  def app=(app)
    @app = Capybara.app = app
  end

  def rodauth(&block)
    (@rodauth_blocks ||= []) << block
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
    rodauth_blocks = @rodauth_blocks
    opts = rodauth_opts(type)

    opts[:json] = jwt_only ? :only : true

    app.plugin(:rodauth, opts) do
      rodauth_blocks.reverse_each do |rodauth_block|
        instance_exec(&rodauth_block)
      end
    end
    app.route(&block)
    app.precompile_rodauth_templates unless @no_precompile
    self.app = app
  end

  def setup_application
    rodauth do
      db RODADB
      enable :http_basic_auth, :oauth
      oauth_application_default_scope TEST_SCOPES.first
      oauth_application_scopes TEST_SCOPES
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

  def login(opts = {})
    visit(opts[:path] || "/login") unless opts[:visit] == false
    fill_in "Login", with: opts.fetch(:login, "foo@example.com")
    fill_in "Password", with: opts.fetch(:pass, "0123456789")
    click_button "Login"
  end

  def around
    db.transaction(rollback: :always, savepoint: true, auto_savepoint: true) { super }
  end

  def around_all
    db.transaction(rollback: :always) do
      hash = BCrypt::Password.create("0123456789", cost: BCrypt::Engine::MIN_COST)
      db[:accounts].insert(email: "foo@example.com", status_id: 2, ph: hash)
      super
    end
  end

  def teardown
    Capybara.reset_sessions!
    Capybara.use_default_driver
  end

  def db
    RODADB
  end
end
