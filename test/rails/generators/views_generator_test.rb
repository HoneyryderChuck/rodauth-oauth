# frozen_string_literal: true

require "test_helper"
require "generators/roda/oauth/views_generator"

class ViewsGeneratorTest < Rails::Generators::TestCase
  tests Rodauth::OAuth::Rails::Generators::ViewsGenerator
  destination File.expand_path("#{__dir__}/../../tmp")
  setup :prepare_destination

  test "default views" do
    run_generator

    templates = %w[oauth_authorize]

    templates.each do |template|
      assert_file "app/views/rodauth/#{template}.html.erb"
    end

    assert_no_file "app/views/rodauth/oauth_applications.html.erb"
    assert_no_file "app/views/rodauth/oauth_application.html.erb"
    assert_no_file "app/views/rodauth/new_oauth_application.html.erb"
  end

  test "choosing features" do
    run_generator ["--features", "oauth_applications"]

    %w[oauth_authorize oauth_applications oauth_application new_oauth_application].each do |template|
      assert_file "app/views/rodauth/#{template}.html.erb"
    end
  end


  test "all features" do
    run_generator ["--all"]

    %w[oauth_authorize oauth_applications oauth_application new_oauth_application].each do |template|
      assert_file "app/views/rodauth/#{template}.html.erb"
    end
  end

  test "specifying directory" do
    run_generator %w[--directory oauth]

    assert_file "app/views/oauth/oauth_authorize.html.erb"
    assert_no_directory "app/views/rodauth"
  end

  test "oauth authorize template" do
    run_generator

    assert_file "app/views/rodauth/oauth_authorize.html.erb", <<-ERB.strip_heredoc
      <%= form_tag rodauth.oauth_authorize_path, method: :post do %>
        <h2>The application <%= rodauth.oauth_application[:name] %> would like to access your data.</h2>

        <div class="form-group">
          <h3>Requested grants:</h3>

          <% rodauth.oauth_application[:scopes].split(",").each do |scope| %>
            <% is_default = scope == rodauth.oauth_application_default_scope %>
            <div class="form-check">
              <%= check_box_tag scope, scope, is_default, disabled: is_default, class: "form-check-input" %>
              <%= label_tag scope, scope, class: "form-check-label" %>
            </div>
          <% end %>
          <%= hidden_field_tag :client_id, rodauth.client_id %>
          <%= hidden_field_tag :state, rodauth.state %>
          <%= hidden_field_tag :redirect_uri, rodauth.redirect_uri %>
        </div>
        <div class="form-group">
          <%= submit_tag "Authorize", class: "btn btn-primary" %>
          <%= link_to "Cancel", "\#{rodauth.redirect_uri}?error=access_denied&error_description=The+resource+owner+or+authorization+server+denied+the+request\#{"&state=\#{rodauth.state}" if rodauth.state}", class: "btn btn-danger" %>
        </div>
      <% end %>
    ERB
  end
end
