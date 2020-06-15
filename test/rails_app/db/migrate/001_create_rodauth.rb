# frozen_string_literal: true

version = eval("#{::ActiveRecord::VERSION::MAJOR}.#{::ActiveRecord::VERSION::MINOR}")

superclass = if ActiveRecord.version >= Gem::Version.new("5.0.0")
               ActiveRecord::Migration[version]
             else
               ActiveRecord::Migration
             end

class CreateRodauth < superclass
  self.verbose = false

  def change
    create_table :accounts do |t|
      t.string :email, null: false, index: { unique: true }
      t.string :ph
    end unless table_exists?(:accounts)
  end
end
