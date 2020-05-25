# frozen_string_literal: true

class RodauthApp < Rodauth::Rails::App
  configure do
    enable :login, :http_basic_auth, :oauth

    db DB
    rails_controller { RodauthController }

    skip_status_checks? true
    password_match? do |_password|
      true
    end

    # OAuth
    oauth_application_default_scope TEST_SCOPES.first
    oauth_application_scopes TEST_SCOPES
  end

  route do |r|
    r.rodauth
    rodauth.oauth_applications
  end
end
