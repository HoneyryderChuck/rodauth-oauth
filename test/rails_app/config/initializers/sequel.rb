# frozen_string_literal: true

require "sequel/core"

db = if ENV.key?("DATABASE_URL")
       ENV["DATABASE_URL"]
     elsif RUBY_ENGINE == "jruby"
       "jdbc:sqlite::memory:"
     else
       "sqlite::memory:"
     end

DB = Sequel.connect(db, test: false)
DB.extension :activerecord_connection
