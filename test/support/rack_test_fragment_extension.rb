# frozen_string_literal: true

if RUBY_VERSION < "2.5"
  module RackTestFragmentExtensions
    def process_and_follow_redirects(_, path, *)
      @current_fragment = build_uri(path).fragment
      super
    end

    def process(_, path, *)
      new_uri = build_uri(path)
      @current_fragment = new_uri.fragment || @current_fragment
      super
    end

    def current_url
      last_request.url
      uri = build_uri(last_request.url)
      uri.fragment = @current_fragment if @current_fragment
      uri.to_s
    rescue Rack::Test::Error
      ""
    end
  end

  Capybara::RackTest::Browser.prepend(RackTestFragmentExtensions)
end
