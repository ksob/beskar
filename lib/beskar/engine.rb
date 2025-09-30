module Beskar
  class Engine < ::Rails::Engine
    isolate_namespace Beskar

    initializer "beskar.middleware" do |app|
      app.config.middleware.use ::Beskar::Middleware::RequestAnalyzer
    end

    initializer "beskar.warden_callbacks", after: :load_config_initializers do |app|
      if defined?(Warden)
        Warden::Manager.after_set_user except: :fetch do |user, auth, opts|
          if user.respond_to?(:track_authentication_event) && auth.request
            user.track_authentication_event(auth.request, :success)
          end
        end

        Warden::Manager.before_failure do |env, opts|
          if env && defined?(User)
            request = ActionDispatch::Request.new(env)
            User.track_failed_authentication(request, opts[:scope])
          end
        end
      end
    end

    # Add engine migrations to host app's migration paths
    initializer "beskar.append_migrations" do |app|
      # Don't add migrations if we're inside the engine itself (testing)
      if !root.to_s.include?(app.root.to_s) && !app.root.to_s.include?(root.to_s)
        engine_migrations = root.join("db", "migrate").to_s

        # Add to Rails paths
        app.config.paths["db/migrate"] << engine_migrations
      end
    end

    # Ensure ActiveRecord sees the engine migrations after initialization
    # config.after_initialize do |app|
    #   unless root.to_s.include?(app.root.to_s)
    #     engine_migrations = root.join("db", "migrate").to_s

    #     # Update ActiveRecord::Tasks paths
    #     current_paths = Array(ActiveRecord::Tasks::DatabaseTasks.migrations_paths)
    #     current_paths << engine_migrations
    #     ActiveRecord::Tasks::DatabaseTasks.migrations_paths = current_paths.uniq
    #   end
    # end
  end
end
