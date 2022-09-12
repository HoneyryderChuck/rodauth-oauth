# frozen_string_literal: true

require "test_helper"

class RodauthOauthOidcWebfingerTest < OIDCIntegration
  include Rack::Test::Methods

  def test_oidc_webfinger_no_params
    setup_application
    header "Accept", "application/jrd+json"

    get("/.well-known/webfinger")

    assert last_response.status == 400
  end

  def test_oidc_webfinger_no_resource
    skip
    setup_application
    get("/.well-known/webfinger?resource=user@example.com")

    assert last_response.status == 404
  end

  def test_oidc_webfinger_with_resource
    setup_application
    get("/.well-known/webfinger?resource=#{account[:email]}")

    assert last_response.status == 200
    assert json_body == {
      "subject" => account[:email],
      "links" => [{
        "rel" => "http://openid.net/specs/connect/1.0/issuer",
        "href" => "http://example.org"
      }]
    }
  end

  private

  def setup_application(*args)
    super(*args, &:load_webfinger_route)
  end
end
