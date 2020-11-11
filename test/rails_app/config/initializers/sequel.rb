# frozen_string_literal: true

require "sequel/core"

db = if ENV.key?("DATABASE_URL") && ENV["DATABASE_URL"] !~ /sqlite/
       db_uri = URI.parse(ENV["DATABASE_URL"])
       if RUBY_ENGINE == "jruby"
         if db_uri.scheme == "sqlite3"
           "jdbc:sqlite://"
         elsif db_uri.scheme == "mysql"
           "jdbc:mysql://"
         elsif !db_uri.scheme.start_with?("jdbc")
           "jdbc:#{db_uri.scheme}://"
         else
           "#{db_uri.scheme}://"
         end
       else
         "#{db_uri.scheme}://"
       end
     elsif RUBY_ENGINE == "jruby"
       "jdbc:sqlite::memory:"
     else
       "sqlite::memory:"
     end

RAILSDB = Sequel.connect(db, test: false)
RAILSDB.extension :activerecord_connection
