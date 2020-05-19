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
RuboCop::RakeTask.new(:rubocop) do |task|
  task.options += %W[-c.rubocop-#{RUBY_MAJOR_MINOR}.yml]
end

task :"test:ci" => %i[test rubocop]
task default: :test
