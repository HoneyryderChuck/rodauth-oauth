# frozen_string_literal: true

require "roda"
require "sequel/core"
require "securerandom"
require "net/http"
require "bcrypt"
require "digest/sha1"

module OauthDemo
  class App < Roda
    if (url = ENV.delete("RODAUTH_DATABASE_URL") || ENV.delete("DATABASE_URL"))
      DB = Sequel.connect(url)
    else
      DB = Sequel.sqlite(File.join(__dir__, "test.db"))
      Sequel.extension :migration
      Sequel::Migrator.run(DB, File.expand_path("../../test/migrate", __dir__))
    end
    if ENV.delete("RODAUTH_DEMO_LOGGER")
      require "logger"
      DB.loggers << Logger.new($stdout)
    end

    DB.extension :date_arithmetic
    DB.freeze

    # OAuth with myself
    client_id = Digest::SHA1.hexdigest("http://localhost:9292/callback")
    application = DB[:oauth_applications].where(client_id: client_id).first || begin
      email = "admin@localhost.com"
      account_id = DB[:accounts].where(email: email).get(:id) || begin
        hash = ::BCrypt::Password.create("password", cost: BCrypt::Engine::MIN_COST)

        DB[:accounts].insert(email: email, status_id: 2, ph: hash)
      end

      application_id = DB[:oauth_applications].insert(
        client_id: Digest::SHA1.hexdigest("http://localhost:9292/callback"),
        client_secret: BCrypt::Password.create(client_id),
        name: "Myself",
        description: "About myself",
        redirect_uri: "http://localhost:9292/callback",
        homepage_url: "http://localhost:9292",
        scopes: "profile.read",
        account_id: account_id
      )
      DB[:oauth_applications].where(id: application_id).first
    end

    opts[:root] = File.dirname(__FILE__)

    plugin :render, escape: true
    plugin :flash
    plugin :common_logger
    plugin :route_csrf

    secret = ENV.delete("RODAUTH_SESSION_SECRET") || SecureRandom.random_bytes(64)
    plugin :sessions, secret: secret, key: "rodauth-demo.session"

    plugin :rodauth, json: true, csrf: :route_csrf do
      db DB
      enable :login, :logout, :create_account, :remember, :http_basic_auth, :oauth
      account_password_hash_column :ph
      title_instance_variable :@page_title
      hmac_secret secret
    end

    plugin :error_handler do |e|
      @page_title = "Internal Server Error"
      view content: "#{h e.class}: #{h e.message}<br />#{e.backtrace.map { |line| h line }.join('<br />')}"
    end

    plugin :not_found do
      @page_title = "File Not Found"
      view content: ""
    end

    route do |r|
      check_csrf! unless r.env["CONTENT_TYPE"] =~ %r{application/json}
      rodauth.load_memory
      r.rodauth

      r.root do
        @application = application
        view "index"
      end

      r.on "callback" do
        if r.params["error"]
          flash[:error] = "Authorization failed: #{r.params['error_description'] || r.params['error']}"
          r.redirect "/"
        end

        code = r.params["code"]

        uri = URI("http://localhost:9292/oauth-token")
        http = Net::HTTP.new(uri.host, uri.port)
        request = Net::HTTP::Post.new(uri.request_uri)
        request.body = JSON.dump({
                                   "grant_type" => "authorization_code",
                                   "code" => code,
                                   "client_id" => application[:client_id],
                                   "client_secret" => application[:client_id],
                                   "redirect_uri" => application[:redirect_uri]
                                 })
        request["content-type"] = "application/json"
        response = http.request(request)

        raise "Unexpected error on token generation, #{response.body}" unless response.code.to_i == 200

        view(inline: response.body)
      end

      rodauth.require_authentication
      rodauth.oauth_applications
    end

    freeze
  end
end
