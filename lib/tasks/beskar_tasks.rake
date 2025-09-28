namespace :beskar do
  desc "Show Beskar engine status and migration information"
  task :status => :environment do
    puts "Beskar Engine Status"
    puts "===================="
    puts "Engine root: #{Beskar::Engine.root}"
    puts "Migrations found in engine: #{Dir[File.join(Beskar::Engine.root, 'db', 'migrate', '*.rb')].count}"
    puts "Host app migration paths: #{Rails.application.paths['db/migrate'].to_a.join(', ')}"
    puts ""
    puts "Engine migrations are automatically available to the host application."
    puts "Run 'rails db:migrate:status' to see all available migrations."
  end

  desc "Check if engine migrations are properly loaded"
  task :check_migrations => :environment do
    engine_migrations = Dir[File.join(Beskar::Engine.root, 'db', 'migrate', '*.rb')]

    if engine_migrations.any?
      puts "✓ Found #{engine_migrations.count} engine migration(s):"
      engine_migrations.each do |migration|
        migration_name = File.basename(migration, '.rb')
        puts "  - #{migration_name}"
      end
    else
      puts "✗ No engine migrations found"
    end

    migration_paths = Rails.application.paths['db/migrate'].to_a
    engine_path = File.join(Beskar::Engine.root, 'db', 'migrate')

    if migration_paths.include?(engine_path)
      puts "✓ Engine migrations path is registered with Rails"
    else
      puts "✗ Engine migrations path is NOT registered with Rails"
      puts "  Expected: #{engine_path}"
      puts "  Current paths: #{migration_paths.join(', ')}"
    end
  end
end
