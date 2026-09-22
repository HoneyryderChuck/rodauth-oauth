if SimpleCov::VERSION >= "1.0.0"
 SimpleCov.skip ".bundle/"
 SimpleCov.skip "vendor/"
 SimpleCov.skip "test/"
 commands = [RUBY_ENGINE, RUBY_VERSION, ENV.fetch("DATABASE_URL", "")[%r{(\w+):(//|:)}, 1], ENV["JWT_LIB"], ENV["BUNDLE_GEMFILE"]].compact
 SimpleCov.command_name commands.join("-")
 SimpleCov.coverage_dir "coverage/#{commands}"
else
  SimpleCov.start do
    add_filter ".bundle/"
    add_filter "vendor/"
    add_filter "test/"
    commands = [RUBY_ENGINE, RUBY_VERSION, ENV.fetch("DATABASE_URL", "")[%r{(\w+):(//|:)}, 1], ENV["JWT_LIB"], ENV["BUNDLE_GEMFILE"]].compact
    command_name commands.join("-")
    coverage_dir "coverage/#{commands}"
  end
end
