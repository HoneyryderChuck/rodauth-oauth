# frozen_string_literal: true

require "json"
require "roda"
require "sequel/core"
require "securerandom"
require "net/http"
require "bcrypt"
require "digest/sha1"

AUTHORIZATION_SERVER = ENV.fetch("AUTHORIZATION_SERVER_URI", "http://localhost:9292")

if ENV.key?("CLIENT_ID") && ENV.key?("CLIENT_SECRET")
  CLIENT_ID = ENV["CLIENT_ID"]
  CLIENT_SECRET = ENV["CLIENT_SECRET"]
else
  # test application
  TEST_APPLICATION_PARAMS = {
    client_name: "Resourcing",
    description: "About resourcing",
    scopes: "",
    token_endpoint_auth_method: "client_secret_basic",
    grant_types: %w[client_credentials],
    redirect_uris: ["http://localhost:9294"],
    client_uri: "http://localhost:9294"
  }.freeze

  puts "registering client application...."
  auth_server_uri = URI(AUTHORIZATION_SERVER)
  http = Net::HTTP.new(auth_server_uri.host, auth_server_uri.port)
  # get endpoint from metadata
  request = Net::HTTP::Get.new("/.well-known/oauth-authorization-server")
  request["accept"] = "application/json"
  response = http.request(request)
  raise "Unexpected error on client registration, #{response.body}" unless response.code.to_i == 200

  metadata = JSON.parse(response.body, symbolize_names: true)

  register_url = URI(metadata[:registration_endpoint])
  request = Net::HTTP::Post.new(register_url.request_uri)
  request.body = JSON.dump(TEST_APPLICATION_PARAMS)
  request["content-type"] = "application/json"
  request["accept"] = "application/json"
  request["authorization"] = "admin@localhost.com"
  response = http.request(request)
  raise "Unexpected error on client registration, #{response.body}" unless response.code.to_i == 201

  fields = JSON.parse(response.body, symbolize_names: true)
  CLIENT_ID = fields[:client_id]
  CLIENT_SECRET = fields[:client_secret]
end

class ResourceServer < Roda
  plugin :common_logger

  plugin :rodauth, json: true do
    enable :oauth_resource_server
    use_date_arithmetic? false
    authorization_server_url AUTHORIZATION_SERVER
    before_introspection_request do |request|
      request.basic_auth(CLIENT_ID, CLIENT_SECRET)
    end
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

  Rack::Server.start(
    app: ResourceServer, Port: 9294
  )
end
