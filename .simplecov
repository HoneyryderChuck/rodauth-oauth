SimpleCov.skip ".bundle/"
SimpleCov.skip "vendor/"
SimpleCov.skip "test/"
commands = [RUBY_ENGINE, RUBY_VERSION, ENV.fetch("DATABASE_URL", "")[%r{(\w+):(//|:)}, 1], ENV["JWT_LIB"], ENV["BUNDLE_GEMFILE"]].compact
SimpleCov.command_name commands.join("-")
SimpleCov.coverage_dir "coverage/#{commands}"
