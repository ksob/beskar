module Beskar
  class Configuration
    attr_accessor :enable_waf, :waf_ruleset, :rate_limiting, :security_tracking

    def initialize
      @enable_waf = false # Default to off
      @waf_ruleset = :default
      @security_tracking = {
        enabled: true,
        track_successful_logins: true,
        track_failed_logins: true,
        auto_analyze_patterns: true
      }
      @rate_limiting = {
        ip_attempts: {
          limit: 10,
          period: 1.hour,
          exponential_backoff: true
        },
        account_attempts: {
          limit: 5,
          period: 15.minutes,
          exponential_backoff: true
        },
        global_attempts: {
          limit: 100,
          period: 1.minute,
          exponential_backoff: false
        }
      }
    end

    def security_tracking_enabled?
      @security_tracking[:enabled]
    end

    def track_successful_logins?
      security_tracking_enabled? && @security_tracking[:track_successful_logins]
    end

    def track_failed_logins?
      security_tracking_enabled? && @security_tracking[:track_failed_logins]
    end

    def auto_analyze_patterns?
      security_tracking_enabled? && @security_tracking[:auto_analyze_patterns]
    end
  end
end
