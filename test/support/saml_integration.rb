# frozen_string_literal: true

require "saml_idp"
require "onelogin/ruby-saml"
require_relative File.join(__dir__, "roda_integration")

SamlIdp.configure do |config|
  service_providers = {
    "http://example.com" => {
      fingerprint: SamlIdp::Default::FINGERPRINT,
      metadata_url: "http://example.com/saml/metadata",

      # We now validate AssertionConsumerServiceURL will match the MetadataURL set above.
      # *If* it's not going to match your Metadata URL's Host, then set this so we can validate the host using this list
      response_hosts: ["example.com"]
    }
  }

  # Find ServiceProvider metadata_url and fingerprint based on our settings
  config.service_provider.finder = lambda { |issuer_or_entity_id|
    service_providers[issuer_or_entity_id]
  }

  config.name_id.formats = { # All 2.0
    email_address: ->(principal) { principal[:email] },
    transient: ->(principal) { principal[:id] },
    persistent: ->(_p) { principal[:id] }
  }
end

class SAMLIntegration < RodaIntegration
  private

  def oauth_application(params = {})
    super(params.merge(
      homepage_url: "http://example.com",
      redirect_uri: "http://example.com/callback"
    ))
  end

  def roda(type = nil, &block)
    jwt_only = type == :jwt

    app = Class.new(Base)
    app.opts[:unsupported_block_result] = :raise
    app.opts[:unsupported_matcher] = :raise
    app.opts[:verbatim_string_matcher] = true
    rodauth_blocks = @rodauth_blocks
    opts = rodauth_opts(type)

    opts[:json] = jwt_only ? :only : true

    app.plugin(:rodauth, name: :saml) do
      db RODADB
      account_password_hash_column :ph
      enable :saml
    end
    app.plugin(:rodauth, opts) do
      account_password_hash_column :ph
      rodauth_blocks.reverse_each do |rodauth_block|
        instance_exec(&rodauth_block)
      end
    end
    app.route(&block)
    app.precompile_rodauth_templates unless @no_precompile
    self.app = app
  end

  def setup_application
    feature = oauth_feature
    scopes = test_scopes

    rodauth do
      db RODADB
      enable feature
      oauth_application_default_scope scopes.first
      oauth_application_scopes scopes

      require_authorizable_account do
        scope.rodauth(:saml).require_login
      end
    end

    roda do |r|
      r.rodauth
      r.rodauth(:saml)

      r.on "callback" do
        r.params["SAMLResponse"]
      end

      r.root do
        flash["error"] || flash["notice"] || "Unauthorized"
      end

      yield(rodauth) if block_given?
      rodauth.authenticated_by.include?("saml")
      rodauth.require_oauth_authorization

      r.on "private" do
        r.get do
          flash["error"] || flash["notice"] || "Authorized"
        end
      end
    end
  end

  def oauth_feature
    :oauth_saml
  end

  def login(opts = {})
    visit(opts[:path] || make_saml_request("http://example.com/callback")) unless opts[:visit] == false
    fill_in "Login", with: opts.fetch(:login, "foo@example.com")
    fill_in "Password", with: opts.fetch(:pass, "0123456789")
    click_button "Login"
    # this is needed because this user agent doesn't run javascript
    click_button "Submit"
  end

  def make_saml_request(requested_saml_acs_url)
    auth_request = OneLogin::RubySaml::Authrequest.new
    auth_request.create(saml_settings(requested_saml_acs_url))
  end

  def saml_settings(saml_acs_url)
    settings = OneLogin::RubySaml::Settings.new
    settings.assertion_consumer_service_url = saml_acs_url
    settings.issuer = oauth_application[:homepage_url]
    settings.idp_sso_target_url = "http://example.com/saml-login"
    settings.assertion_consumer_logout_service_url = "http://foo.example.com/saml-logout"
    settings.idp_cert_fingerprint = SamlIdp::Default::FINGERPRINT
    settings.name_identifier_format = SamlIdp::Default::NAME_ID_FORMAT
    settings
  end
end
