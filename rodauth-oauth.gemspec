# frozen_string_literal: true

require File.expand_path("lib/rodauth/oauth/version", __dir__)

Gem::Specification.new do |spec|
  spec.name          = "rodauth-oauth"
  spec.version       = Rodauth::OAuth::VERSION
  spec.platform      = Gem::Platform::RUBY
  spec.authors       = ["Tiago Cardoso"]
  spec.email         = ["cardoso_tiago@hotmail.com"]

  spec.summary       = "Implementation of the OAuth 2.0 protocol on top of rodauth."
  spec.description   = "Implementation of the OAuth 2.0 protocol on top of rodauth."
  spec.homepage      = "https://gitlab.com/honeyryderchuck/rodauth-oauth"
  spec.required_ruby_version = Gem::Requirement.new(">= 2.5.0")

  spec.metadata = {
    "homepage_uri" => "https://honeyryderchuck.gitlab.io/rodauth-oauth/",
    "documentation_uri" => "https://honeyryderchuck.gitlab.io/rodauth-oauth/rdoc/",
    "bug_tracker_uri" => "https://gitlab.com/honeyryderchuck/rodauth-oauth/issues",
    "source_code_uri" => "https://gitlab.com/honeyryderchuck/rodauth-oauth",
    "changelog_uri" => "https://gitlab.com/honeyryderchuck/rodauth-oauth/-/blob/master/CHANGELOG.md",
    "rubygems_mfa_required" => "true"
  }
  spec.license = "Apache-2.0"

  spec.files = Dir["LICENSE.txt", "README.md", "MIGRATION-GUIDE-V1.md", "lib/**/*.{rb,erb}", "templates/*", "locales/**/*.yml", "CHANGELOG.md",
                   "doc/release_notes/*.md"]
  spec.extra_rdoc_files = Dir["LICENSE.txt", "README.md", "MIGRATION-GUIDE-V1.md", "CHANGELOG.md", "doc/release_notes/*.md"]

  spec.require_paths = ["lib"]

  spec.add_dependency "rodauth", "~> 2.0"
end
