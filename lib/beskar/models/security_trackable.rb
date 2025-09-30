module Beskar
  module Models
    module SecurityTrackable
      extend ActiveSupport::Concern

      included do
        has_many :security_events, class_name: 'Beskar::SecurityEvent', as: :user, dependent: :destroy

        # Hook into Devise callbacks if Devise is present and available
        if defined?(Devise) && respond_to?(:after_database_authentication)
          # Track successful authentications
          after_database_authentication :track_successful_login
        end
      end

      module ClassMethods
        def track_failed_authentication(request, scope)
          # Skip tracking if disabled in configuration
          unless Beskar.configuration.track_failed_logins?
            Rails.logger.debug "[Beskar] Failed login tracking disabled in configuration"
            return
          end

          # Create a security event for failed authentication
          # We don't have a specific user, so we'll track by IP/session
          metadata = {
            scope: scope.to_s,
            attempted_email: request.params.dig('user', 'email') || request.params.dig(scope, 'email'),
            timestamp: Time.current.iso8601,
            session_id: request.session.id,
            request_path: request.path,
            referer: request.referer,
            accept_language: request.headers['Accept-Language'],
            x_forwarded_for: request.headers['X-Forwarded-For'],
            x_real_ip: request.headers['X-Real-IP'],
            device_info: Beskar::Services::DeviceDetector.detect(request.user_agent),
            geolocation: Beskar::Services::GeolocationService.locate(request.ip)
          }

          attempted_email = request.params.dig('user', 'email') || request.params.dig(scope, 'email')

          Beskar::SecurityEvent.create!(
            user: nil,
            event_type: 'login_failure',
            ip_address: request.ip,
            user_agent: request.user_agent,
            attempted_email: attempted_email,
            metadata: metadata,
            risk_score: calculate_failure_risk_score(request)
          )

          # Trigger rate limiting check
          Beskar::Services::RateLimiter.check_authentication_attempt(request, :failure)
        end

        private

        def calculate_failure_risk_score(request)
          score = 10 # Base score for failed login

          # Use device detector for more comprehensive risk assessment
          device_detector = Beskar::Services::DeviceDetector.new
          score += device_detector.calculate_user_agent_risk(request.user_agent)

          # Additional failure-specific risk factors
          score += 10 if request.params.dig('user', 'password')&.length.to_i > 50

          # Use geolocation service for location-based risk
          geolocation_service = Beskar::Services::GeolocationService.new
          score += geolocation_service.calculate_location_risk(request.ip)

          [score, 100].min # Cap at 100
        end
      end

      def track_successful_login
        # Skip tracking if disabled in configuration
        unless Beskar.configuration.track_successful_logins?
          Rails.logger.debug "[Beskar] Successful login tracking disabled in configuration"
          return
        end

        if current_request = request_from_context
          track_authentication_event(current_request, :success)
        end
      rescue => e
        Rails.logger.warn "[Beskar] Failed to track successful login: #{e.message}"
        nil
      end

      def track_authentication_event(request, result)
        return unless request

        # Check if tracking is enabled for this event type
        if result == :success && !Beskar.configuration.track_successful_logins?
          Rails.logger.debug "[Beskar] Successful login tracking disabled in configuration"
          return
        elsif result == :failure && !Beskar.configuration.track_failed_logins?
          Rails.logger.debug "[Beskar] Failed login tracking disabled in configuration"
          return
        end

        event_type = result == :success ? 'login_success' : 'login_failure'

        security_event = security_events.build(
          event_type: event_type,
          ip_address: request.ip,
          user_agent: request.user_agent,
          attempted_email: self.email,
          metadata: extract_security_context(request),
          risk_score: calculate_risk_score(request, result)
        )

        if security_event.save
          # Perform background security analysis
          analyze_suspicious_patterns_async if result == :success && Beskar.configuration.auto_analyze_patterns?

          # Update rate limiting
          Beskar::Services::RateLimiter.check_authentication_attempt(request, result, self)
        end

        security_event
      end

      def analyze_suspicious_patterns_async
        # Skip analysis if disabled in configuration
        unless Beskar.configuration.auto_analyze_patterns?
          Rails.logger.debug "[Beskar] Auto pattern analysis disabled in configuration"
          return
        end

        # Queue background job for detailed analysis
        Beskar::SecurityAnalysisJob.perform_later(self.id, 'login_success') if defined?(Beskar::SecurityAnalysisJob)
      rescue => e
        Rails.logger.warn "[Beskar] Failed to queue security analysis: #{e.message}"
      end

      def recent_failed_attempts(within: 1.hour)
        security_events.where(
          event_type: 'login_failure',
          created_at: within.ago..Time.current
        )
      end

      def recent_successful_logins(within: 24.hours)
        security_events.where(
          event_type: 'login_success',
          created_at: within.ago..Time.current
        )
      end

      def suspicious_login_pattern?
        # Check for rapid successive attempts
        recent_attempts = recent_failed_attempts(within: 5.minutes)
        return true if recent_attempts.count >= 3

        # Check for geographic anomalies
        recent_logins = recent_successful_logins(within: 4.hours).includes(:security_events)
        return true if geographic_anomaly_detected?(recent_logins)

        false
      end

      private

      def request_from_context
        # Try to get request from various contexts
        if defined?(Current) && Current.respond_to?(:request)
          Current.request
        elsif Thread.current[:request]
          Thread.current[:request]
        elsif defined?(ActionController::Base) && ActionController::Base.respond_to?(:current_request)
          ActionController::Base.current_request
        elsif defined?(Warden) && Warden::Manager.respond_to?(:current_request)
          Warden::Manager.current_request
        end
      rescue => e
        Rails.logger.debug "[Beskar] Could not get request from context: #{e.message}"
        nil
      end

      def extract_security_context(request)
        {
          timestamp: Time.current.iso8601,
          session_id: request.session.id,
          request_path: request.path,
          referer: request.referer,
          accept_language: request.headers['Accept-Language'],
          x_forwarded_for: request.headers['X-Forwarded-For'],
          x_real_ip: request.headers['X-Real-IP'],
          device_info: Beskar::Services::DeviceDetector.detect(request.user_agent),
          geolocation: Beskar::Services::GeolocationService.locate(request.ip)
        }
      end



      def calculate_risk_score(request, result)
        base_score = result == :success ? 1 : 25
        score = base_score

        # Use dedicated services for risk assessment
        device_detector = Beskar::Services::DeviceDetector.new
        score += device_detector.calculate_user_agent_risk(request.user_agent)

        # Mobile device login during late hours
        if device_detector.mobile?(request.user_agent) && Time.current.hour.between?(22, 6)
          score += 5
        end

        # Account-specific risk factors
        score += 20 if recent_failed_attempts(within: 10.minutes).count >= 2

        # Geographic risk assessment
        geolocation_service = Beskar::Services::GeolocationService.new
        recent_locations = recent_successful_logins(within: 4.hours).map do |event|
          event.metadata&.dig('geolocation')
        end.compact

        score += geolocation_service.calculate_location_risk(
          request.ip,
          recent_locations,
          recent_successful_logins(within: 4.hours).last&.created_at&.to_i
        )

        [score, 100].min # Cap at 100
      end

      def geographic_anomaly_detected?(recent_logins)
        # Placeholder for geographic anomaly detection
        # Would implement haversine formula and impossible travel detection
        false
      end
    end
  end
end
