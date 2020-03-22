# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "securerandom"
require "capybara"
require "capybara/dsl"
require "minitest/autorun"

require "sequel"
require "roda"

DB = Sequel.sqlite(File.join(Dir.tmpdir, "roda-oauth.db"))
