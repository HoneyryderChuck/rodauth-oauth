# frozen_string_literal: true

require "base64"
require "net/http"
require "securerandom"
require "roda"

AUTHORIZATION_SERVER = ENV.fetch("AUTHORIZATION_SERVER_URI", "http://localhost:9292")
RESOURCE_SERVER = ENV.fetch("RESOURCE_SERVER_URI", "http://localhost:9292/books")
REDIRECT_URI = "http://localhost:9293/callback"
CLIENT_ID = ENV.fetch("CLIENT_ID", "CLIENT_ID")
CLIENT_SECRET = ENV.fetch("CLIENT_SECRET", CLIENT_ID)

class ClientApplication < Roda
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
              <button type="submit" class="btn btn-outline-primary">Authenticate</button>
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
    r.assets
    r.root do
      inline = if (token = session["access_token"])
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
               else
                 <<-HTML
                  <p class="lead">
                    You can use this application to test the OpenID Connect framework.
                    Once you authenticate, you'll see a list of books available in the resource server, and your name.
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
          "scope" => "openid email profile books.read",
          "state" => state
        }.map { |k, v| "#{CGI.escape(k)}=#{CGI.escape(v)}" }.join("&")

        authorize_url = URI.parse(AUTHORIZATION_SERVER)
        authorize_url.path = "/oauth-authorize"
        authorize_url.query = query_params

        r.redirect authorize_url.to_s
      end
    end

    r.on "callback" do
      #
      # This is the redirect uri, where the authorization server redirects to with grant information for
      # the user to generate an access token.
      #
      r.get do
        session_state = session.delete("state")

        if session_state
          state = request.params["state"]
          if !state || state != session_state
            flash[:error] = "state doesn't match, CSRF Attack!!!"
            r.redirect "/"
          end
        end

        if r.params["error"]
          flash[:error] = "Authorization failed: #{r.params['error_description'] || r.params['error']}"
          r.redirect "/"
        end

        code = r.params["code"]

        response = json_request(:post, "#{AUTHORIZATION_SERVER}/oauth-token", params: {
                                  "grant_type" => "authorization_code",
                                  "code" => code,
                                  "client_id" => CLIENT_ID,
                                  "client_secret" => CLIENT_SECRET,
                                  "redirect_uri" => REDIRECT_URI
                                })

        session["id_token"] = response[:id_token]
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
          json_request(:post, "#{AUTHORIZATION_SERVER}/oauth-revoke", params: {
                         "client_id" => CLIENT_ID,
                         "client_secret" => CLIENT_SECRET,
                         "token_type_hint" => "access_token",
                         "token" => session["access_token"]
                       })
        rescue StandardError # rubocop:disable Lint/SuppressedException
        end

        session.delete("id_token")
        session.delete("access_token")
        session.delete("refresh_token")
        flash["notice"] = "You are logged out!"
        r.redirect "/"
      end
    end
  end

  private

  def json_request(meth, uri, headers: {}, params: {})
    uri = URI(uri)
    http = Net::HTTP.new(uri.host, uri.port)
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
  require "rack"

  Rack::Server.start(
    app: ClientApplication, Port: 9293
  )
end
