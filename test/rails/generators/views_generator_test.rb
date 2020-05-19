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
end
