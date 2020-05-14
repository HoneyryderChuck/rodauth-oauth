# frozen_string_literal: true

version = File.read(File.expand_path("VERSION", __dir__)).strip

Gem::Specification.new do |spec|
  spec.name          = "roda-oauth"
  spec.version       = version
  spec.platform      = Gem::Platform::RUBY
  spec.authors       = ["Tiago Cardoso"]
  spec.email         = ["cardoso_tiago@hotmail.com"]

  spec.summary       = "Implementation of the OAuth 2.0 protocol on top of rodauth."
  spec.description   = "Implementation of the OAuth 2.0 protocol on top of rodauth."
  spec.homepage      = "https://gitlab.com/honeyryderchuck/roda-oauth"
  # spec.required_ruby_version = Gem::Requirement.new(">= 2.3.0")

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://gitlab.com/honeyryderchuck/roda-oauth"
  spec.metadata["changelog_uri"] = "https://gitlab.com/honeyryderchuck/roda-oauth/-/blob/master/CHANGELOG.md"

  spec.files = Dir["LICENSE.txt", "README.md", "lib/**/*.rb", "CHANGELOG.md"]
  spec.extra_rdoc_files = Dir["LICENSE.txt", "README.md", "CHANGELOG.md"]

  spec.require_paths = ["lib"]
end
