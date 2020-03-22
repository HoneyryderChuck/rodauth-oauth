# frozen_string_literal: true

require "test_helper"

class RodaOauthAuthorizeTest < Minitest::Test
  include Capybara::DSL

  def test_authorize_get_public_area
    visit "/"
    assert page.html == "Unauthorized"
  end

  def test_authorize_get_private_area_unauthorized
    visit "/private"
    assert page.html == "Unauthorized"
  end

  def test_authorize_get_authorize_not_logged_in
    visit "/oauth-authorize"
    assert page.current_path == "/login",
           "was redirected instead to #{page.current_path}"
  end

  private

  def setup
    Capybara.app = Class.new(Roda) do
      include Capybara::DSL

      plugin :flash
      plugin :render, layout_opts: { path: "test/views/layout.str" }
      plugin(:not_found) { raise "path #{request.path_info} not found" }

      plugin :sessions, secret: SecureRandom.random_bytes(64),
                        key: "rack.session"

      use Rack::Session::Cookie, secret: "0123456789"

      plugin :rodauth do
        enable :oauth
      end

      route do |r|
        r.rodauth

        r.root do
          "Unauthorized"
        end

        rodauth.oauth_authorize

        r.on "private" do
          r.get do
            "Authorized"
          end
        end
      end
    end
  end
end
