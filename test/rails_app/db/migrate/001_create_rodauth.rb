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
    unless table_exists?(:account_statuses)
      create_table :account_statuses do |t|
        t.string :name, null: false, index: { unique: true }
      end
      execute <<-SQL
  INSERT INTO account_statuses (id, name) values
  (1, 'Unverified'),
  (2, 'Verified'),
  (3, 'Closed')
      SQL
    end


    create_table :accounts do |t|
      t.string :email, null: false, index: { unique: true }
      t.string :ph
      t.integer :status_id, references: :account_statuses, null: false, default: 1
    end unless table_exists?(:accounts)
  end
end
