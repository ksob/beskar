module Beskar
  module Middleware
    class RequestAnalyzer
      def initialize(app)
        @app = app
      end

      def call(env)
        request = ActionDispatch::Request.new(env)

        # Run security checks here
        if threat_detected?(request)
          return [ 403, { "Content-Type" => "text/html" }, [ "Forbidden" ] ]
        end

        @app.call(env)
      end

      private

      def threat_detected?(request)
        # Logic will be added in later phases
        false
      end
    end
  end
end
