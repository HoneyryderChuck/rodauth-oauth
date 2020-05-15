version = eval("#{::ActiveRecord::VERSION::MAJOR}.#{::ActiveRecord::VERSION::MINOR}")

if ActiveRecord.version >= Gem::Version.new("5.0.0")
  superclass = ActiveRecord::Migration[version]
else
  superclass = ActiveRecord::Migration
end

class CreateRodauth < superclass
  self.verbose = false

  def change
    create_table :accounts do |t|
      t.string :email, null: false, index: { unique: true }
      t.string :ph
    end
  end
end
