#!/usr/bin/env ruby

# Demo script showing basic Beskar functionality
# Run this from the beskar gem directory with: ruby demo_basic_functionality.rb

require_relative 'test/test_helper'
require 'ostruct'

puts "🔒 Beskar Security Gem - Basic Functionality Demo"
puts "=" * 60

# Initialize configuration
Beskar.configure do |config|
  config.security_tracking = {
    enabled: true,
    track_successful_logins: true,
    track_failed_logins: true,
    auto_analyze_patterns: true
  }

  config.rate_limiting = {
    ip_attempts: {
      limit: 5,        # Lower limit for demo
      period: 1.hour,
      exponential_backoff: true
    },
    account_attempts: {
      limit: 3,        # Lower limit for demo
      period: 15.minutes,
      exponential_backoff: true
    }
  }
end

puts "✅ Configuration loaded"
puts "   IP Rate Limit: #{Beskar.configuration.rate_limiting[:ip_attempts][:limit]} attempts per hour"
puts "   Account Rate Limit: #{Beskar.configuration.rate_limiting[:account_attempts][:limit]} attempts per 15 minutes"
puts

# Create a test user
user = User.create!(email: 'demo@example.com', password: 'password123')
puts "👤 Created test user: #{user.email}"
puts

# Demo 1: Track successful login
puts "📊 Demo 1: Tracking Successful Login"
puts "-" * 40

success_request = OpenStruct.new(
  ip: '192.168.1.100',
  user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
  path: '/users/sign_in',
  session: OpenStruct.new(id: 'demo_session_success'),
  headers: { 'Accept-Language' => 'en-US,en;q=0.9' }
)

event = user.track_authentication_event(success_request, :success)
puts "   Event Type: #{event.event_type}"
puts "   IP Address: #{event.ip_address}"
puts "   Risk Score: #{event.risk_score}/100"
puts "   Device: #{event.device_info['browser']} on #{event.device_info['platform']}"
puts "   Mobile: #{event.device_info['mobile']}"
puts

# Demo 2: Track failed login attempts
puts "📊 Demo 2: Tracking Failed Login Attempts"
puts "-" * 40

3.times do |i|
  failed_request = OpenStruct.new(
    ip: '10.0.0.1',
    user_agent: 'curl/7.68.0',  # Suspicious user agent
    path: '/users/sign_in',
    session: OpenStruct.new(id: "demo_session_fail_#{i}"),
    headers: {},
    params: { 'user' => { 'email' => 'attacker@malicious.com' } }
  )

  User.track_failed_authentication(failed_request, :user)
  puts "   Failed attempt ##{i + 1} recorded (Risk Score: #{Beskar::SecurityEvent.last.risk_score})"
end

puts "   Total failed attempts: #{Beskar::SecurityEvent.login_failures.count}"
puts

# Demo 3: Rate Limiting
puts "📊 Demo 3: Rate Limiting in Action"
puts "-" * 40

test_ip = '203.0.113.1'
rate_limiter = Beskar::Services::RateLimiter.new(test_ip, user)

puts "   Initial state:"
puts "     IP allowed: #{rate_limiter.allowed?}"
puts "     Attempts remaining: #{rate_limiter.attempts_remaining}"

# Simulate failed attempts to trigger rate limiting
test_request = OpenStruct.new(ip: test_ip)
5.times do |i|
  result = Beskar::Services::RateLimiter.check_authentication_attempt(test_request, :failure, user)
  puts "   Attempt #{i + 1}: allowed=#{result[:allowed]}, remaining=#{result[:remaining] || 0}"
end

puts
rate_limiter_after = Beskar::Services::RateLimiter.new(test_ip, user)
if rate_limiter_after.allowed?
  puts "   ✅ IP still allowed"
else
  puts "   🚫 IP now rate limited!"
  puts "     Time until reset: #{rate_limiter_after.time_until_reset} seconds"
end

puts

# Demo 4: Attack Pattern Detection
puts "📊 Demo 4: Attack Pattern Detection"
puts "-" * 40

# Create distributed attack pattern (multiple IPs, same user)
attack_ips = ['192.168.1.1', '192.168.1.2', '192.168.1.3']
attack_ips.each_with_index do |ip, i|
  user.security_events.create!(
    event_type: 'login_failure',
    ip_address: ip,
    user_agent: 'AttackBot/1.0',
    risk_score: 75,
    created_at: Time.current - (i * 30), # 30 seconds apart
    metadata: { attempted_email: user.email }
  )
end

attack_analyzer = Beskar::Services::RateLimiter.new('192.168.1.1', user)
pattern_type = attack_analyzer.attack_pattern_type

puts "   Pattern detected: #{pattern_type}"
puts "   Suspicious pattern: #{attack_analyzer.suspicious_pattern?}"

case pattern_type
when :distributed_single_account
  puts "   🚨 ALERT: Distributed attack detected - multiple IPs targeting single account"
when :brute_force_single_account
  puts "   ⚠️  WARNING: Brute force attack from single IP"
when :single_ip_multiple_accounts
  puts "   🔍 NOTICE: Credential stuffing attempt detected"
else
  puts "   ℹ️  No specific attack pattern detected"
end

puts

# Demo 5: Security Event Analysis
puts "📊 Demo 5: Security Event Analysis"
puts "-" * 40

total_events = Beskar::SecurityEvent.count
success_events = Beskar::SecurityEvent.login_successes.count
failure_events = Beskar::SecurityEvent.login_failures.count
high_risk_events = Beskar::SecurityEvent.high_risk.count

puts "   Security Event Summary:"
puts "     Total events: #{total_events}"
puts "     Successful logins: #{success_events}"
puts "     Failed logins: #{failure_events}"
puts "     High-risk events: #{high_risk_events}"

if user.suspicious_login_pattern?
  puts "   🚨 User has suspicious login patterns!"
  recent_failures = user.recent_failed_attempts(within: 1.hour)
  puts "     Recent failed attempts: #{recent_failures.count}"
else
  puts "   ✅ No suspicious patterns detected for this user"
end

puts

# Demo 6: Configuration and Reset
puts "📊 Demo 6: Rate Limit Reset"
puts "-" * 40

puts "   Before reset:"
blocked_result = Beskar::Services::RateLimiter.check_ip_rate_limit(test_ip)
puts "     IP #{test_ip} allowed: #{blocked_result[:allowed]}"

# Reset rate limits
Beskar::Services::RateLimiter.reset_rate_limit(ip_address: test_ip, user: user)
puts "   Rate limits reset for IP and user"

after_reset = Beskar::Services::RateLimiter.check_ip_rate_limit(test_ip)
puts "   After reset:"
puts "     IP #{test_ip} allowed: #{after_reset[:allowed]}"

puts

# Summary
puts "🎉 Demo Complete!"
puts "=" * 60
puts "This demo showed:"
puts "• ✅ Authentication event tracking with risk scoring"
puts "• ✅ Device and browser detection from user agents"
puts "• ✅ Rate limiting with exponential backoff"
puts "• ✅ Attack pattern recognition (distributed attacks, brute force, credential stuffing)"
puts "• ✅ Security event analysis and reporting"
puts "• ✅ Administrative controls (rate limit reset)"
puts
puts "Next steps:"
puts "• Add geographic anomaly detection with IP geolocation"
puts "• Implement JavaScript challenge system for bot detection"
puts "• Build real-time dashboard for security monitoring"
puts "• Add webhook notifications for critical security events"

# Cleanup
puts
puts "🧹 Cleaning up demo data..."
Beskar::SecurityEvent.delete_all
User.delete_all
Rails.cache.clear
puts "✅ Cleanup complete"
