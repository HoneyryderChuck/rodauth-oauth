# frozen_string_literal: true

DB = begin
  db = if ENV.key?("DATABASE_URL")
         if RUBY_ENGINE == "jruby"
           # All of this magic is because the DATABASE_URL are the kind of random URIS parsed
           # by Rails, but it's incompatible with sequel, which follows the standards of JDBC.
           #
           # for this reason, sequel is initiated by parsing out the correct URI from the env var.
           if ENV["DATABASE_URL"].match(/sqlite3(.*)/)
             # AR: sqlite3::memory:
             # Sequel: jdbc:sqlite::memory:
             # can't test jruby sqlite in parallel mode
             # https://stackoverflow.com/questions/10707434/sqlite-in-a-multithreaded-java-application
             ENV.delete("PARALLEL")
             Sequel.connect("jdbc:sqlite#{Regexp.last_match(1)}")
           elsif ENV["DATABASE_URL"].match(/mysql(.*)/)
             # AR: mysql://user:pass@host/db
             # Sequel: jdbc:mysql://user:pass@host/db
             Sequel.connect("jdbc:mysql#{Regexp.last_match(1)}")
           elsif !ENV["DATABASE_URL"].start_with?("jdbc")
             # AR: postgresql://user:pass@host/db
             # Sequel: jdbc:postgresql://host/db?user=user&password=pass
             uri = URI.parse(ENV["DATABASE_URL"])
             uri.query = "user=#{uri.user}&password=#{uri.password}"
             uri.user = nil
             uri.password = nil
             Sequel.connect("jdbc:#{uri}")
           else
             Sequel.connect(ENV["DATABASE_URL"])
           end
         elsif ENV["DATABASE_URL"].match(/sqlite3(.*)/)
           Sequel.connect("sqlite#{Regexp.last_match(1)}")
         else
           Sequel.connect(ENV["DATABASE_URL"])
         end
       else
         Sequel.sqlite
       end

  # I've checked what rails parallel tests do, and they seem to load a different database per test
  # anyway (no transactional tests), and that can't be made with sqlite memory anyway.
  #
  ENV.delete("PARALLEL") if defined?(Rails) && db.adapter_scheme == :sqlite

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
      account_password_hash_column :ph
      rodauth_blocks.reverse_each do |rodauth_block|
        instance_exec(&rodauth_block)
      end
    end
    app.route(&block)
    app.precompile_rodauth_templates unless @no_precompile
    self.app = app
  end

  def oauth_feature
    :oauth
  end

  def setup_application(*features)
    features << oauth_feature
    scopes = test_scopes
    rodauth do
      db DB
      enable :login, :logout, :http_basic_auth, *features
      login_return_to_requested_location? true
      oauth_application_default_scope scopes.first
      oauth_application_scopes scopes
    end
    roda do |r|
      r.rodauth

      r.on "callback" do
        "Callback"
      end

      r.root do
        view inline: (flash["error"] || flash["notice"] || "Unauthorized")
      end

      yield(rodauth) if block_given?
      rodauth.require_oauth_authorization

      r.on "private" do
        r.get do
          view inline: (flash["error"] || flash["notice"] || "Authorized")
        end
      end
    end
  end

  def login(opts = {})
    unless opts[:visit] == false
      if !page.html.empty? && page.has_content?("nav")
        click_link("Login")
      else
        visit("/login")
      end
    end
    fill_in "Login", with: opts.fetch(:login, "foo@example.com")
    fill_in "Password", with: opts.fetch(:pass, "0123456789")
    click_button "Login"
  end

  def logout
    click_link("Logout")
    click_on "Logout"
  end

  def set_authorization_header(token = oauth_token)
    header "Authorization", "Bearer #{token[:token]}"
  end

  def around
    db.transaction(rollback: :always, savepoint: true, auto_savepoint: true) do
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
    DB
  end

  def generate_hashed_token(token)
    Base64.urlsafe_encode64(Digest::SHA256.digest(token))
  end

  def verify_token_common_response(data)
    assert data["token_type"] == "bearer"
    assert !data["expires_in"].nil?
    assert !data["access_token"].nil?
  end

  def verify_refresh_token_response(data, prev_token)
    verify_token_common_response(data)
    assert data["access_token"] != prev_token[:token]
    assert (Time.now.to_i + data["expires_in"]) > prev_token[:expires_in].to_i
  end

  def verify_access_token_response(data, oauth_token)
    verify_token_common_response(data)
    assert data["access_token"] == oauth_token[:token]
    assert data["refresh_token"] == oauth_token[:refresh_token]
  end

  def verify_oauth_grant_revoked(oauth_token)
    oauth_grant = db[:oauth_grants].where(id: oauth_token[:oauth_grant_id]).first
    assert !oauth_grant[:revoked_at].nil?, "oauth grant should be revoked"
  end

  parallelize_me! if ENV.key?("PARALLEL")
end
