# frozen_string_literal: true

require "test_helper"

class RodaOauthAuthorizeTest < Minitest::Test
  include Capybara::DSL

  def test_authorize_get_public_area
    setup_application 
    visit "/"
    assert page.html == "Unauthorized"
  end

  def test_authorize_get_private_area_unauthorized
    setup_application
    visit "/private"
    assert page.html == "Unauthorized"
  end

  def test_authorize_get_authorize_not_logged_in
    setup_application
    visit "/oauth/authorize"
    assert page.current_path == "/login",
           "was redirected instead to #{page.current_path}"
  end

  def test_authorize_get_authorize_logged_in
    setup_application
    login
    visit "/oauth/authorize"
    assert page.current_path == "/", "was redirected instead to #{page.current_path}"
  end

  private

  def setup_application
    rodauth do
      enable :oauth
      password_match? do |_password|
        true
      end
    end
    roda do |r|
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
