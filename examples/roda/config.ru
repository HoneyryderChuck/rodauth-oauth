# frozen_string_literal: true

$LOAD_PATH.unshift(::File.expand_path("../../lib", __FILE__))
require ::File.expand_path("../oauth_demo", __FILE__)
run OauthDemo::App.app
