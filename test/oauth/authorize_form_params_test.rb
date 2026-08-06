# frozen_string_literal: true

require "test_helper"

class RodauthOauthAuthorizeFormParamsTest < RodaIntegration
  def test_authorize_form_forwards_request_params
    setup_application(:oauth_pkce, :oauth_resource_indicators)
    login

    visit "/authorize?client_id=#{oauth_application[:client_id]}&response_type=code&response_mode=query" \
          "&state=STATE&access_type=offline&code_challenge=#{PKCE_CHALLENGE}&code_challenge_method=S256" \
          "&resource=#{CGI.escape('https://resource.com')}"

    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"

    assert_hidden_field("client_id", oauth_application[:client_id])
    assert_hidden_field("response_type", "code")
    assert_hidden_field("response_mode", "query")
    assert_hidden_field("state", "STATE")
    assert_hidden_field("access_type", "offline")
    assert_hidden_field("code_challenge", PKCE_CHALLENGE)
    assert_hidden_field("code_challenge_method", "S256")
    assert_hidden_field("resource", "https://resource.com")
  end

  def test_authorize_form_forwards_repeated_resource_indicators
    setup_application(:oauth_resource_indicators)
    login

    visit "/authorize?client_id=#{oauth_application[:client_id]}&response_type=code" \
          "&resource=#{CGI.escape('https://resource.com')}&resource=#{CGI.escape('https://resource2.com')}"

    assert_hidden_field("resource", "https://resource.com")
    assert_hidden_field("resource", "https://resource2.com")
  end

  def test_authorize_form_forwards_custom_params
    rodauth do
      authorize_form_params do
        super().tap do |params|
          if (tenant = param_or_nil("tenant"))
            params << { "name" => "tenant", "value" => tenant, "type" => "hidden" }
          end
        end
      end
    end
    setup_application
    login

    visit "/authorize?client_id=#{oauth_application[:client_id]}&response_type=code&tenant=acme"

    assert_hidden_field("tenant", "acme")
  end

  private

  def assert_hidden_field(name, value)
    assert page.has_css?("input[type=hidden][name='#{name}'][value='#{value}']", visible: :all),
           "expected the authorize form to carry #{name}=#{value} over"
  end
end
