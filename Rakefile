# frozen_string_literal: true

require "bundler/gem_tasks"
require "rdoc/task"
require "rake/testtask"

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.libs << "lib"
  t.test_files = FileList["test/**/*_test.rb"]
  t.warning = false
end

begin
  require "rubocop/rake_task"
  desc "Run rubocop"
  RuboCop::RakeTask.new(:rubocop)
rescue LoadError
end

namespace :coverage do
  desc "Aggregates coverage reports"
  task :report do
    return unless ENV.key?("CI")

    require "simplecov"

    SimpleCov.collate Dir["coverage/**/.resultset.json"]
  end
end

CI_TASKS = %i[test rubocop]

task "test:ci": CI_TASKS

task default: :test

# Doc

rdoc_opts = ["--line-numbers", "--title", "Rodauth OAuth: OAuth 2.0 and OpenID for rodauth"]

begin
  gem "hanna-nouveau"
  rdoc_opts.concat(["-f", "hanna"])
rescue Gem::LoadError
end

rdoc_opts.concat(["--main", "README.md"])
RDOC_FILES = %w[README.md CHANGELOG.md lib/**/*.rb] + Dir["doc/*.rdoc"] + Dir["doc/release_notes/*.md"]

RDoc::Task.new do |rdoc|
  rdoc.rdoc_dir = "rdoc"
  rdoc.options += rdoc_opts
  rdoc.rdoc_files.add RDOC_FILES
end

RDoc::Task.new(:website_rdoc) do |rdoc|
  rdoc.rdoc_dir = "rdoc"
  rdoc.options += rdoc_opts
  rdoc.rdoc_files.add RDOC_FILES
end

desc "Check configuration method documentation"
task :check_method_doc do
  docs = {}
  Dir["doc/*.rdoc"].sort.each do |f|
    meths = File.binread(f).split("\n").grep(/\A(\w+[!?]?(\([^\)]+\))?) :: /).map { |line| line.split(/( :: |\()/, 2)[0] }.sort
    docs[File.basename(f).sub(/\.rdoc\z/, "")] = meths unless meths.empty?
  end
  require "rodauth/oauth"
  begin
    require "jwt"
  rescue LoadError
  end
  docs.each do |f, doc_meths|
    require "./lib/rodauth/features/#{f}"
    feature = Rodauth::FEATURES[f.to_sym]
    meths = (feature.auth_methods + feature.auth_value_methods + feature.auth_private_methods).map(&:to_s).sort
    unless (undocumented_meths = meths - doc_meths).empty?
      puts "#{f} undocumented methods: #{undocumented_meths.join(', ')}"
    end
    unless (bad_doc_meths = doc_meths - meths).empty?
      puts "#{f} documented methods that don't exist: #{bad_doc_meths.join(', ')}"
    end
  end
  puts "#{docs.values.flatten.length} total documented configuration methods"
end

desc "Builds jekyll data"
task :prepare_jekyll_data do
  require "yaml"

  FileUtils.mkdir_p("data")
  `git tag -l`.lines(chomp: true)
              .map { |v| v[1..-1] }
              .sort_by(&Gem::Version.method(:new))
              .reverse
              .map { |v| { "name" => v, "path" => "#{v.tr('.', '_')}_md.html" } }
              .then { |v| YAML.dump(v) }
              .then { |output| File.write("data/versions.yml", output) }
end

desc "Builds Homepage"
task prepare_website: %i[website_rdoc prepare_jekyll_data] do
  require "fileutils"
  FileUtils.rm_rf("wiki")
  system("git clone https://gitlab.com/os85/rodauth-oauth.wiki.git wiki")
  Dir.glob("wiki/*.md") do |path|
    data = File.read(path)
    name = File.basename(path, ".md")
    title = name == "home" ? "Wiki" : name.split("-").map(&:capitalize).join(" ")
    layout = name == "home" ? "page" : "wiki"

    header = "---\n" \
             "layout: #{layout}\n" \
             "title: #{title}\n" \
             "---\n\n"
    File.write(path, header + data)
  end
end
