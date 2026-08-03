# frozen_string_literal: true

require "test_helper"

# The authorize form is rendered to the resource owner with values taken from the authorization
# request and from the client application, neither of which the authorization server controls.
class RodauthOauthAuthorizeEscapingTest < RodaIntegration
  PAYLOAD = '"><script>alert(1)</script><input value="'

  def test_authorize_escapes_request_params
    setup_application
    login

    visit "/authorize?client_id=#{oauth_application[:client_id]}&response_type=code&state=#{CGI.escape(PAYLOAD)}"

    assert page.current_path == "/authorize",
           "was redirected instead to #{page.current_path}"
    assert_no_script_tag
    assert_includes page.html, "&quot;&gt;&lt;script&gt;"
  end

  def test_authorize_escapes_request_params_in_cancel_link
    setup_application
    login

    visit "/authorize?client_id=#{oauth_application[:client_id]}&response_type=code&state=#{CGI.escape(PAYLOAD)}"

    cancel_url = page.find_link("Cancel")["href"]
    assert cancel_url.include?("state=#{CGI.escape(PAYLOAD)}"),
           "the cancel link dropped or mangled the state: #{cancel_url}"
    assert_no_script_tag
  end

  def test_authorize_escapes_client_name
    setup_application
    login

    application = set_oauth_application(client_id: "CLIENT_ID2", name: "<script>alert(1)</script>", homepage_url: nil)
    visit "/authorize?client_id=#{application[:client_id]}&response_type=code"

    assert_no_script_tag
    assert_includes page.html, "&lt;script&gt;alert(1)&lt;/script&gt;"
  end

  def test_authorize_escapes_client_name_with_homepage_url
    setup_application
    login

    application = set_oauth_application(client_id: "CLIENT_ID2", name: "<script>alert(1)</script>",
                                        homepage_url: "https://example.com")
    visit "/authorize?client_id=#{application[:client_id]}&response_type=code"

    assert_no_script_tag
  end

  private

  def assert_no_script_tag
    assert !page.html.include?("<script>alert(1)</script>"),
           "unescaped markup was rendered into the authorize page"
  end
end
