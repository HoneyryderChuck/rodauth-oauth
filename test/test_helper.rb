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
FileUtils.rm(db_path)

DB = Sequel.sqlite(db_path)
DB.loggers << Logger.new($stderr)

Sequel.extension :migration
require "rodauth/migrations"
Sequel::Migrator.run(DB, 'test/migrate')


class Minitest::Test
  include Minitest::Hooks
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