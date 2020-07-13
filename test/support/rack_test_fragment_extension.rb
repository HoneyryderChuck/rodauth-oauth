# frozen_string_literal: true

module RackTestFragmentExtensions
  def env_for(uri, _)
    env = super
    env["QUERY_STRING"] << "##{uri.fragment}" if uri.fragment
    env
  end
end

Rack::Test::Session.prepend(RackTestFragmentExtensions)
