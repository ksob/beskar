FactoryBot.define do
  factory :security_event, class: "Beskar::SecurityEvent" do
    association :user
    event_type { "login_success" }
    ip_address { "192.168.1.100" }
    user_agent { "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" }
    risk_score { 10 }
    metadata do
      {
        "timestamp" => Time.current.iso8601,
        "session_id" => "session_#{SecureRandom.hex(8)}",
        "request_path" => "/login",
        "device_info" => {
          "browser" => "Chrome 91",
          "platform" => "Windows 10.0",
          "mobile" => false
        }
      }
    end

    trait :login_success do
      event_type { "login_success" }
      risk_score { rand(1..15) }
    end

    trait :login_failure do
      event_type { "login_failure" }
      risk_score { rand(20..50) }
      metadata do
        {
          "timestamp" => Time.current.iso8601,
          "session_id" => "session_#{SecureRandom.hex(8)}",
          "request_path" => "/login",
          "attempted_email" => "user@example.com",
          "device_info" => {
            "browser" => "Chrome 91",
            "platform" => "Windows 10.0",
            "mobile" => false
          }
        }
      end
    end

    trait :high_risk do
      risk_score { rand(70..89) }
      ip_address { "203.0.113.1" }
      user_agent { "curl/7.68.0" }
    end

    trait :critical_risk do
      risk_score { rand(90..100) }
      ip_address { "203.0.113.1" }
      user_agent { "" }
      metadata do
        {
          "timestamp" => Time.current.iso8601,
          "attempted_email" => "admin@example.com",
          "suspicious_patterns" => ["rapid_attempts", "bot_user_agent"]
        }
      end
    end

    trait :mobile_device do
      user_agent { "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1" }
      metadata do
        {
          "timestamp" => Time.current.iso8601,
          "session_id" => "mobile_session_#{SecureRandom.hex(8)}",
          "device_info" => {
            "browser" => "Safari 14",
            "platform" => "iOS 14.7.1",
            "mobile" => true
          }
        }
      end
    end

    trait :bot_user_agent do
      user_agent { "Googlebot/2.1 (+http://www.google.com/bot.html)" }
      risk_score { rand(60..80) }
    end

    trait :anonymous do
      user { nil }
      user_type { nil }
      event_type { "login_failure" }
      risk_score { rand(80..95) }
      metadata do
        {
          "timestamp" => Time.current.iso8601,
          "attempted_email" => "nonexistent@example.com",
          "anonymous_attempt" => true
        }
      end
    end

    trait :with_geolocation do
      metadata do
        {
          "timestamp" => Time.current.iso8601,
          "session_id" => "session_#{SecureRandom.hex(8)}",
          "geolocation" => {
            "country" => "US",
            "city" => "New York",
            "latitude" => 40.7128,
            "longitude" => -74.0060
          },
          "device_info" => {
            "browser" => "Chrome 91",
            "platform" => "Windows 10.0",
            "mobile" => false
          }
        }
      end
    end

    trait :recent do
      created_at { 5.minutes.ago }
    end

    trait :old do
      created_at { 2.hours.ago }
    end
  end
end
