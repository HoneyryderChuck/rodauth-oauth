# frozen_string_literal: true

require "base64"
require "net/http"
require "securerandom"
require "roda"

AUTHORIZATION_SERVER = ENV.fetch("AUTHORIZATION_SERVER_URI", "http://localhost:9292")
REDIRECT_URI = "http://localhost:9293/callback"
CLIENT_ID = ENV.fetch("CLIENT_APPLICATION_ID", "http://localhost:9293")

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
      <script crossorigin src="https://cdnjs.cloudflare.com/ajax/libs/babel-standalone/6.26.0/babel.min.js"></script>
      <script crossorigin src="https://unpkg.com/react@16.3.1/umd/react.development.js"></script>
      <script crossorigin src="https://unpkg.com/react-dom@16.3.1/umd/react-dom.development.js"></script>
      <style>
      .error {border: 1px #a00 solid;
      span.error_message {
        color: #a00;
        background-color: #ffffe0;
        border-color: 1px solid #eeeed0;
        padding: 5px 2px;
        display: inline-block; 
      }
      span.error_message:before {
          content: "(!) "
      }
      input.rodauth_hidden {
        display: none;
      }
      </style>
    
      <meta id="access-token" name="access-token" content="<%= session["access_token"] %>" />
      </head>
      <body>
      <nav class="navbar navbar-default" role="navigation">
        <div class="container">
          <a class="navbar-brand" href="/">Rodauth Oauth Demo - Book Store Client Application</a>
          <ul class="navbar-nav ml-auto nav-flex-icons">
            <% if !session["access_token"] %>
              <form action="/authorize" class="navbar-form pull-right" method="post">
                <%= csrf_tag("/authorize") %>
                <button type="submit" class="btn btn-primary form-control auth-button">Authorize</a>
              </form>
            <% else %>
              <li id="oauth-username"></li>
              <li class="nav-item">
                <form action="/logout" class="navbar-form pull-right" method="post">
                  <%= csrf_tag("/logout") %>
                  <input class="btn btn-primary form-control auth-button" type="submit" value="Logout" />
                </form>
              </li>
            <% end %>
          </ul>
        </div>
      </nav>
      <div class="container">
        <% if flash['notice'] %>
          <div class="alert alert-success"><p><%= flash['notice'] %></p></div>
        <% end %>
        <% if flash['error'] %>
          <div class="alert alert-danger"><p><%= flash['error'] %></p></div>
        <% end %>
        <h1><%= @page_title %></h1>
    
        <%= yield %>
      </div>
      </body>
    </html>
  LAYOUT

  plugin :flash
  plugin :common_logger

  secret = ENV.delete("RODAUTH_SESSION_SECRET") || SecureRandom.random_bytes(64)
  plugin :sessions, secret: secret, key: "client-application.session"

  plugin :route_csrf

  route do |r|
    r.root do
      view inline: <<-HTML
        <div class="container"><div id="root"></div></div>
        <!-- JAVASCRIPT GOES HERE */ -->
        <script type="text/babel">

          const TOKEN = document.getElementById('access-token').getAttribute('content');

          class App extends React.Component {
            state = {
              profile: null,
              books: null,
            };


            render() {

              if (!TOKEN) {
                return (
                  <div className="row">
                    <h2>Not authorized to read books, please authorize!</h2>
                  </div>
                );
              }

              return (
                <div className="row books-app">
                  <h1>Books</h1>
                  <ul>
                    <li>Test</li>
                  </ul>
                </div>
              );
            }
          }

          ReactDOM.render(<App />, document.getElementById("root"));
        </script>
      HTML
    end

    r.on "authorize" do
      r.post do
        state = Base64.urlsafe_encode64(SecureRandom.hex(32))
        session["state"] = state

        query_params = {
          "redirect_uri" => REDIRECT_URI,
          "client_id" => CLIENT_ID,
          "scope" => "profile.read books.read",
          "state" => state
        }.map { |k, v| "#{CGI.escape(k)}=#{CGI.escape(v)}" }.join("&")

        authorize_url = URI.parse(AUTHORIZATION_SERVER)
        authorize_url.path = "/oauth-authorize"
        authorize_url.query = query_params

        r.redirect authorize_url.to_s
      end
    end

    r.on "callback" do
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

        response = json_request(:post, "#{AUTHORIZATION_SERVER}/oauth-token", {
                                  "grant_type" => "authorization_code",
                                  "code" => code,
                                  "client_id" => CLIENT_ID,
                                  "client_secret" => CLIENT_ID,
                                  "redirect_uri" => REDIRECT_URI
                                })

        session["access_token"] = response["access_token"]
        session["refresh_token"] = response["refresh_token"]

        r.redirect "/"
      end
    end
  end

  private

  def json_request(meth, uri, params = {})
    uri = URI(uri)
    http = Net::HTTP.new(uri.host, uri.port)
    case meth
    # when :get
    when :post
      request = Net::HTTP::Post.new(uri.request_uri)
      request.body = JSON.dump(params)
      request["content-type"] = "application/json"
      request["accept"] = "application/json"
      response = http.request(request)
      raise "Unexpected error on token generation, #{response.body}" unless response.code.to_i == 200

      JSON.parse(response.body)
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
