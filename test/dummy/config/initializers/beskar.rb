Beskar.configure do |config|
  # Global monitor-only mode - creates ban records but doesn't enforce them
  config.monitor_only = true

  # WAF Configuration with auto-blocking enabled
  config.waf = {
    enabled: true,
    auto_block: true,                # Automatically create ban records after threshold
    block_threshold: 3,              # Create ban after 3 violations
    violation_window: 1.hour,        # Count violations within this window
    block_durations: [               # Escalating ban durations
      1.hour,
      6.hours,
      24.hours,
      7.days
    ],
    permanent_block_after: 10,       # Permanent ban after 10 violations
    create_security_events: true     # Create SecurityEvent records
  }

  # Enable geolocation with MaxMind City database (if available)
  # In CI/environments without the database, falls back to mock provider
  city_db_path = Rails.root.join('config', 'GeoLite2-City.mmdb').to_s

  config.geolocation = {
    provider: File.exist?(city_db_path) ? :maxmind : :mock,
    maxmind_city_db_path: File.exist?(city_db_path) ? city_db_path : nil,
    cache_ttl: 4.hours
  }

  # Optional: Configure rate limiting
  config.rate_limiting = {
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

  # Optional: Configure security tracking
  config.security_tracking = {
    enabled: true,
    track_successful_logins: true,
    track_failed_logins: true,
    auto_analyze_patterns: true
  }

  # Optional: Configure IP whitelist (add your development IPs if needed)
  # config.ip_whitelist = ['127.0.0.1', '::1']
end
