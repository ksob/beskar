FactoryBot.define do
  factory :banned_ip, class: "Beskar::BannedIp" do
    sequence(:ip_address) { |n| "192.168.#{n % 255}.#{(n / 255) % 255}" }
    reason { "Suspicious activity detected" }
    banned_at { Time.current }
    expires_at { Time.current + 1.hour }
    permanent { false }
    violation_count { 1 }
    metadata do
      {
        "user_agent" => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "path" => "/login",
        "timestamp" => Time.current.iso8601
      }
    end

    trait :temporary do
      permanent { false }
      expires_at { Time.current + 30.minutes }
    end

    trait :permanent do
      permanent { true }
      expires_at { nil }
      reason { "Permanent ban - severe violation" }
    end

    trait :expired do
      banned_at { 2.hours.ago }
      expires_at { 1.hour.ago }
      permanent { false }
    end

    trait :active do
      banned_at { 10.minutes.ago }
      expires_at { 50.minutes.from_now }
      permanent { false }
    end

    trait :high_violation do
      violation_count { 5 }
      reason { "Multiple violations detected" }
      metadata do
        {
          "user_agent" => "curl/7.68.0",
          "violations" => ["brute_force", "sql_injection", "xss_attempt"],
          "timestamp" => Time.current.iso8601
        }
      end
    end

    trait :waf_violation do
      reason { "WAF: SQL Injection attempt" }
      metadata do
        {
          "user_agent" => "sqlmap/1.5",
          "path" => "/api/users",
          "payload" => "1' OR '1'='1",
          "waf_rule" => "sql_injection",
          "timestamp" => Time.current.iso8601
        }
      end
    end

    trait :rate_limit do
      reason { "Rate limit exceeded" }
      expires_at { Time.current + 15.minutes }
      metadata do
        {
          "requests_count" => 150,
          "time_window" => "1 minute",
          "limit" => 60,
          "path" => "/api/search",
          "timestamp" => Time.current.iso8601
        }
      end
    end

    trait :brute_force do
      reason { "Brute force attack detected" }
      expires_at { Time.current + 2.hours }
      violation_count { 3 }
      metadata do
        {
          "failed_attempts" => 25,
          "attempted_usernames" => ["admin", "root", "administrator"],
          "time_window" => "5 minutes",
          "timestamp" => Time.current.iso8601
        }
      end
    end

    trait :bot_detected do
      reason { "Malicious bot detected" }
      permanent { true }
      metadata do
        {
          "user_agent" => "BadBot/1.0",
          "honeypot_triggered" => true,
          "suspicious_patterns" => ["no_referrer", "direct_admin_access", "automated_requests"],
          "timestamp" => Time.current.iso8601
        }
      end
    end

    trait :tor_exit_node do
      sequence(:ip_address) { |n| "185.220.#{100 + (n % 50)}.#{n % 255}" }
      reason { "Tor exit node" }
      expires_at { Time.current + 24.hours }
      metadata do
        {
          "tor_node" => true,
          "country" => "Unknown",
          "risk_score" => 75,
          "timestamp" => Time.current.iso8601
        }
      end
    end

    trait :with_details do
      metadata do
        {
          "user_agent" => "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
          "path" => "/admin/login",
          "details" => "Multiple failed login attempts with various usernames",
          "geolocation" => {
            "country" => "CN",
            "city" => "Beijing",
            "latitude" => 39.9042,
            "longitude" => 116.4074
          },
          "timestamp" => Time.current.iso8601
        }
      end
    end

    trait :recent do
      banned_at { 5.minutes.ago }
      expires_at { 55.minutes.from_now }
    end

    trait :old do
      banned_at { 7.days.ago }
      expires_at { 7.days.ago + 1.hour }
    end

    trait :about_to_expire do
      banned_at { 50.minutes.ago }
      expires_at { 10.minutes.from_now }
    end
  end
end
