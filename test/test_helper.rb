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
DB.loggers << Logger.new($stderr)

Sequel.extension :migration
require "rodauth/migrations"
Sequel::Migrator.run(DB, 'test/migrate')


Base = Class.new(Roda)
Base.opts[:check_dynamic_arity] = Base.opts[:check_arity] = :warn
Base.plugin :flash
Base.plugin :render, :views=>'test/views', :layout_opts=>{:path=>'test/views/layout.str'}
Base.plugin(:not_found){raise "path #{request.path_info} not found"}
Base.plugin :common_logger

require 'roda/session_middleware'
Base.opts[:sessions_convert_symbols] = true
Base.use RodaSessionMiddleware, :secret=>SecureRandom.random_bytes(64), :key=>'rack.session'

class Minitest::Test
  include Minitest::Hooks

  def app=(app)
    @app = Capybara.app = app
  end

  def rodauth(&block)
    @rodauth_block = block
  end

   def rodauth_opts(type={})
    opts = type.is_a?(Hash) ? type : {}
    opts[:csrf] = :route_csrf
    opts
  end

  def roda(type=nil, &block)
    app = Class.new(Base)
    app.opts[:unsupported_block_result] = :raise
    app.opts[:unsupported_matcher] = :raise
    app.opts[:verbatim_string_matcher] = true
    rodauth_block = @rodauth_block
    opts = rodauth_opts(type)

    app.plugin(:rodauth, opts) do
      instance_exec(&rodauth_block)
    end
    app.route(&block)
    app.precompile_rodauth_templates unless @no_precompile
    self.app = app
  end

  def oauth_application
    @oauth_application ||= begin
     id = DB[:oauth_applications].insert \
        name: "Foo",
        description: "this is a foo",
        homepage_url: "https://foobar.com",
        callback_url: "https://foobar.com/callback",
        client_id: "CLIENT_ID",
        client_secret: "CLIENT_SECRET",
        grants: %w[profile.read]

      DB[:oauth_applications].filter(id: id).first
    end
  end

  def login(opts={})
    visit(opts[:path]||'/login') unless opts[:visit] == false
    fill_in 'Login', :with=>opts.fetch(:login, 'foo@example.com')
    fill_in 'Password', :with=>opts.fetch(:pass, '0123456789')
    click_button 'Login'
  end

  def around
    DB.transaction(:rollback=>:always, :savepoint=>true, :auto_savepoint=>true){super}
  end
  
  def around_all
    DB.transaction(:rollback=>:always) do
      hash = BCrypt::Password.create('0123456789', :cost=>BCrypt::Engine::MIN_COST)
      DB[:accounts].insert(:email=>'foo@example.com', :status_id=>2, :ph=>hash)
      super
    end
  end

  def teardown
    Capybara.reset_sessions!
    Capybara.use_default_driver
  end
end