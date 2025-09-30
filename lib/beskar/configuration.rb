module Beskar
  class Configuration
    attr_accessor :enable_waf, :waf_ruleset, :rate_limiting, :security_tracking, :risk_based_locking

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
      @risk_based_locking = {
        enabled: false,                    # Master switch for risk-based locking
        risk_threshold: 75,                # Lock account if risk score >= this value
        lock_strategy: :devise_lockable,   # Strategy: :devise_lockable, :custom, :none
        auto_unlock_time: 1.hour,          # Time until automatic unlock (if supported by strategy)
        notify_user: true,                 # Send notification on lock
        log_lock_events: true,             # Create security event for locks
        immediate_signout: false           # Sign out user immediately via Warden callback (requires :lockable)
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

    # Risk-based locking configuration helpers
    def risk_based_locking_enabled?
      @risk_based_locking[:enabled]
    end

    def risk_threshold
      @risk_based_locking[:risk_threshold] || 75
    end

    def lock_strategy
      @risk_based_locking[:lock_strategy] || :devise_lockable
    end

    def auto_unlock_time
      @risk_based_locking[:auto_unlock_time] || 1.hour
    end

    def notify_user_on_lock?
      @risk_based_locking[:notify_user] != false
    end

    def log_lock_events?
      @risk_based_locking[:log_lock_events] != false
    end

    def immediate_signout?
      @risk_based_locking[:immediate_signout] == true
    end
  end
end
