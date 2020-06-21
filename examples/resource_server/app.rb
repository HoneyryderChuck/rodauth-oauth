# frozen_string_literal: true

require "roda"
require "sequel/core"
require "securerandom"
require "net/http"
require "bcrypt"
require "digest/sha1"

AUTHORIZATION_SERVER = ENV.fetch("AUTHORIZATION_SERVER_URI", "http://localhost:9292")
CLIENT_ID = ENV.fetch("CLIENT_ID", "CLIENT_ID")
CLIENT_SECRET = ENV.fetch("CLIENT_SECRET", CLIENT_ID)

class ResourceServer < Roda
  plugin :common_logger

  plugin :rodauth, json: true do
    enable :oauth
    use_date_arithmetic? false
    is_authorization_server? false
    authorization_server_url AUTHORIZATION_SERVER
    oauth_client_id CLIENT_ID
    oauth_client_secret CLIENT_SECRET
  end

  plugin :not_found do
    { "error" => "Resource Not Found" }
  end

  route do |r|
    r.on "books" do
      rodauth.require_oauth_authorization("books.read")
      r.get do
        [
          { "name" => "Anna Karenina", "author" => "Leo Tolstoy" },
          { "name" => "Madame Bovary", "author" => "Gustave Flaubert" },
          { "name" => "War and Peace", "author" => "Leo Tolstoy" },
          { "name" => "The Adventures of Huckleberry Finn", "author" => "Mark Twain" },
          { "name" => "The stories", "author" => "Anton Chekhov" },
          { "name" => "Middlemarch", "author" => "George Eliot" },
          { "name" => "Moby-Dick", "author" => "Herman Melville" },
          { "name" => "Great Expectations", "author" => "Charles Dickens" },
          { "name" => "Crime and Punishment", "author" => "Fyodor Dostoevsky" },
          { "name" => "Emma", "author" => "Jane Austen" }
        ]
      end
    end
  end

  freeze
end

if $PROGRAM_NAME == __FILE__
  require "rack"
  require "rack/cors"

  app = Rack::Builder.app do
    use Rack::Cors, debug: true, logger: Logger.new(STDOUT) do
      allow do
        origins "*"

        resource "*",
                 headers: :any,
                 methods: %i[get post]
      end
    end
    run ResourceServer
  end

  Rack::Server.start(
    app: app, Port: 9294
  )
end
