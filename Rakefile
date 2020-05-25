# frozen_string_literal: true

require "bundler/gem_tasks"
require "rake/testtask"
require "rubocop/rake_task"

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.libs << "lib"
  t.test_files = FileList["test/**/*_test.rb"]
  t.warning = false
end

desc "Run rubocop"
RuboCop::RakeTask.new(:rubocop)

CI_TASKS = RUBY_VERSION < "2.4" ? %i[test] : %i[test rubocop]

task "test:ci": CI_TASKS

task default: :test
