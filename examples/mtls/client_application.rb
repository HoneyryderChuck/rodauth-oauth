# frozen_string_literal: true

require "uri"
require "base64"
require "json"
require "securerandom"
require "jwt"
require "net/http"
require "roda"

require_relative "tls_helpers"

AUTHORIZATION_SERVER = ENV.fetch("AUTHORIZATION_SERVER_URI", "https://localhost:9292")
RESOURCE_SERVER = ENV.fetch("RESOURCE_SERVER_URI", "https://localhost:9292/books")
REDIRECT_URI = "http://localhost:9293/callback"

if ENV.key?("CLIENT_ID") && ENV.key?("CLIENT_SECRET")
  CLIENT_ID = ENV["CLIENT_ID"]
  CLIENT_SECRET = ENV["CLIENT_SECRET"]
else

  # test application
  TEST_APPLICATION_PARAMS = {
    client_name: "Myself",
    description: "About myself",
    scopes: "profile.read books.read",
    token_endpoint_auth_method: "tls_client_auth",
    grant_types: %w[authorization_code refresh_token],
    response_types: %w[code],
    redirect_uris: [REDIRECT_URI],
    client_uri: "http://localhost:9293",
    logo_uri: "http://localhost:9293/logo.png",
    tos_uri: "http://localhost:9293/tos",
    policy_uri: "http://localhost:9293/policy",
    tls_client_auth_subject_dn: "/CN=client"
  }.freeze

  module MTLS
    module_function

    def enable_mtls(http)
      http.use_ssl = true

      # http.ca_path = File.join(__dir__, "ca.pem")

      # client conf
      root_ctx = SelfSignedCert.new("client-root")
      root_cert = root_ctx.cert
      root_key = root_ctx.private_key
      client_ctx = SelfSignedCert.new("client", root_key: root_key, root_cert: root_cert)
      client_cert = client_ctx.cert
      client_key = client_ctx.private_key
      http.cert = client_cert
      http.key = client_key
      http.extra_chain_cert = [root_cert]

      # server conf
      ca_store = OpenSSL::X509::Store.new
      ca_store.add_file(File.join(__dir__, "server-root-cert.pem"))
      ca_store.add_file(File.join(__dir__, "server-cert.pem"))
      http.cert_store = ca_store
    end
  end

  puts "registering client application...."
  auth_server_uri = URI(AUTHORIZATION_SERVER)

  http = Net::HTTP.new(auth_server_uri.host, auth_server_uri.port)

  MTLS.enable_mtls(http)

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

puts "client registered: #{CLIENT_ID}"

class ClientApplication < Roda
  plugin :public, root: File.expand_path("../assets/images", __dir__)
  plugin :render, layout: { inline: <<~LAYOUT }
    <!DOCTYPE html>
    <html>
      <head>
      <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css"
            rel="stylesheet"
            integrity="sha384-Vkoo8x4CGsO3+Hhxv8T/Q5PaXtkKtu6ug5TOeNV6gBiFeWPGFN9MuhOf23Q9Ifjh"
            crossorigin="anonymous"></link>
      <title>Rodauth Oauth Demo - Book Store Client Application</title>
      <%= assets(:css) %>
      </head>
      <body>
        <div class="d-flex flex-column flex-md-row align-items-center p-3 px-md-4 mb-3 bg-white border-bottom box-shadow">
          <h5 class="my-0 mr-md-auto font-weight-normal">Rodauth Oauth Demo - Book Store Application</h5>
          <nav class="my-2 my-md-0 mr-md-3">
            <!-- a class="p-2 text-dark" href="#">Features</a-->
            <!-- a class="p-2 text-dark" href="#">Enterprise</a-->
            <!-- a class="p-2 text-dark" href="#">Support</a-->
            <!-- a class="p-2 text-dark" href="#">Pricing</a-->
          </nav>
          <% if !session["access_token"] %>
            <form action="/authorize" class="navbar-form pull-right" method="post">
              <%= csrf_tag("/authorize") %>
              <button type="submit" class="btn btn-outline-primary">Authorize</button>
            </form>
          <% else %>
            <form action="/logout" class="navbar-form pull-right" method="post">
              <%= csrf_tag("/logout") %>
              <input class="btn btn-outline-primary" type="submit" value="Logout" />
            </form>
          <% end %>
        </div>
        <div class="container">
          <% if flash['notice'] %>
            <div class="alert alert-success"><p><%= flash['notice'] %></p></div>
          <% end %>
          <% if flash['error'] %>
            <div class="alert alert-danger"><p><%= flash['error'] %></p></div>
          <% end %>
          <div class="main px-3 py-3 pt-md-5 pb-md-4 mx-auto text-center">
            <h1 class="display-4">Book Store</h1>
            <%= yield %>
          </div>
        </div>
      </body>
    </html>
  LAYOUT

  plugin :flash
  plugin :common_logger
  plugin :assets, css: "layout.scss", path: File.expand_path("../assets", __dir__)

  secret = ENV.delete("RODAUTH_SESSION_SECRET") || SecureRandom.random_bytes(64)
  plugin :sessions, secret: secret, key: "client-application.session"

  plugin :route_csrf

  route do |r|
    r.public
    r.assets
    r.root do
      inline = if (token = session["access_token"])
                 begin
                   @books = json_request(:get, RESOURCE_SERVER, headers: { "authorization" => "Bearer #{token}" })
                   <<-HTML
                    <div class="books-app">
                      <ul class="list-group">
                        <% @books.each do |book| %>
                          <li class="list-group-item">"<%= book[:name] %>" by <b><%= book[:author] %></b></li>
                        <% end %>
                      </ul>
                    </div>
                   HTML
                 rescue RuntimeError => e
                   <<-HTML
                    <p class="lead">
                      There was an error retrieving the books. Did you authorize the <code>books.read</code> scope?
                      <pre>
                        #{e.message}
                      </pre>
                    </p>
                   HTML
                 end
               else
                 <<-HTML
                  <p class="lead">
                    You can use this application to test the OAuth 2.0 authorization framework.
                    Once you authorize, you'll see a list of books available in the resource server.
                  </p>
                 HTML
               end

      view inline: inline
    end

    r.on "authorize" do
      #
      # This link redirects the user to the authorization server, to perform the authorization step.
      #
      r.post do
        state = Base64.urlsafe_encode64(SecureRandom.hex(32))
        session["state"] = state

        query_params = {
          "redirect_uri" => REDIRECT_URI,
          "client_id" => CLIENT_ID,
          "scope" => "profile.read books.read",
          "response_type" => "code",
          "state" => state
        }.map { |k, v| "#{CGI.escape(k)}=#{CGI.escape(v)}" }.join("&")

        authorize_url = URI.parse(AUTHORIZATION_SERVER)
        authorize_url.path = "/authorize"
        authorize_url.query = query_params

        r.redirect authorize_url.to_s
      end
    end

    r.on "callback" do
      #
      # This is the redirect uri, where the authorization server redirects to with grant information for
      # the user to generate an access token.
      #
      r.post do
        if r.params["error"]
          flash[:error] = "Authorization failed: #{r.params['error_description'] || r.params['error']}"
          r.redirect "/"
        end

        session_state = session.delete("state")

        if session_state
          state = request.params["state"]
          if !state || state != session_state
            flash[:error] = "state doesn't match, CSRF Attack!!!"
            r.redirect "/"
          end
        end

        code = r.params["code"]

        response = json_request(:post, "#{AUTHORIZATION_SERVER}/token", params: {
                                  "grant_type" => "authorization_code",
                                  "code" => code,
                                  "client_id" => CLIENT_ID,
                                  "redirect_uri" => REDIRECT_URI
                                })

        session["access_token"] = response[:access_token]
        session["refresh_token"] = response[:refresh_token]

        r.redirect "/"
      end
    end

    r.on "logout" do
      #
      # This endpoint uses the OAuth revoke endpoint to invalidate an access token.
      #
      r.post do
        begin
          json_request(:post, "#{AUTHORIZATION_SERVER}/revoke", params: {
                         "client_id" => CLIENT_ID,
                         "token_type_hint" => "access_token",
                         "token" => session["access_token"]
                       })
        rescue StandardError # rubocop:disable Lint/SuppressedException
        end

        session.delete("access_token")
        session.delete("refresh_token")
        flash["notice"] = "You are logged out!"
        r.redirect "/"
      end
    end

    r.on "tos" do
      view inline: "Terms of Service"
    end

    r.on "policy" do
      view inline: "Policy"
    end
  end

  private

  def json_request(meth, uri, headers: {}, params: {})
    uri = URI(uri)
    http = Net::HTTP.new(uri.host, uri.port)
    MTLS.enable_mtls(http)
    case meth
    when :get
      request = Net::HTTP::Get.new(uri.request_uri)
      request["accept"] = "application/json"
      headers.each do |k, v|
        request[k] = v
      end
      response = http.request(request)
      raise "Unexpected error on token generation, #{response.body}" unless response.code.to_i == 200

      JSON.parse(response.body, symbolize_names: true)
    when :post
      request = Net::HTTP::Post.new(uri.request_uri)
      request.body = JSON.dump(params)
      request["content-type"] = "application/json"
      request["accept"] = "application/json"
      headers.each do |k, v|
        request[k] = v
      end
      response = http.request(request)
      raise "Unexpected error on token generation, #{response.body}" unless response.code.to_i == 200

      JSON.parse(response.body, symbolize_names: true)
    end
  end

  freeze
end

if $PROGRAM_NAME == __FILE__
  require "rackup"

  Rackup::Server.start(
    app: ClientApplication, Port: 9293
  )
end
