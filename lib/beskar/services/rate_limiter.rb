module Beskar
  module Services
    class RateLimiter
      DEFAULT_CONFIG = {
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
          period: 1.minute
        }
      }.freeze

      class << self
        def check_authentication_attempt(request, result, user = nil)
          ip_address = request.ip

          # Check IP-based rate limiting
          ip_result = check_ip_rate_limit(ip_address)

          # Check account-based rate limiting if we have a user
          account_result = user ? check_account_rate_limit(user) : {allowed: true}

          # Check global rate limiting to prevent system overload
          global_result = check_global_rate_limit

          # Record the attempt
          record_attempt(ip_address, result, user)

          # Return most restrictive result
          most_restrictive_result([ip_result, account_result, global_result])
        end

        def check_ip_rate_limit(ip_address)
          config = Beskar.configuration.rate_limiting&.dig(:ip_attempts) || DEFAULT_CONFIG[:ip_attempts]
          cache_key = "beskar:ip_attempts:#{ip_address}"
          check_rate_limit(cache_key, config)
        end

        def check_account_rate_limit(user)
          config = Beskar.configuration.rate_limiting&.dig(:account_attempts) || DEFAULT_CONFIG[:account_attempts]
          cache_key = "beskar:account_attempts:#{user.class.name}:#{user.id}"
          check_rate_limit(cache_key, config)
        end

        def check_global_rate_limit
          config = Beskar.configuration.rate_limiting&.dig(:global_attempts) || DEFAULT_CONFIG[:global_attempts]
          cache_key = "beskar:global_attempts"
          check_rate_limit(cache_key, config)
        end

        def is_rate_limited?(request, user = nil)
          result = check_authentication_attempt(request, :check, user)
          !result[:allowed]
        end

        def time_until_allowed(request, user = nil)
          result = check_authentication_attempt(request, :check, user)
          result[:retry_after] || 0
        end

        def reset_rate_limit(ip_address: nil, user: nil)
          if ip_address
            Rails.cache.delete("beskar:ip_attempts:#{ip_address}")
            Rails.cache.delete("beskar:ip_backoff:#{ip_address}")
          end

          if user
            cache_key = "beskar:account_attempts:#{user.class.name}:#{user.id}"
            Rails.cache.delete(cache_key)
            Rails.cache.delete("beskar:account_backoff:#{user.class.name}:#{user.id}")
          end
        end

        private

        def check_rate_limit(cache_key, config)
          now = Time.current.to_i
          period = config[:period].to_i
          limit = config[:limit]
          window_start = now - period

          # Get current window data
          window_data = Rails.cache.read(cache_key) || {}

          # Clean old entries
          cleaned_data = window_data.select { |timestamp, _| timestamp.to_i > window_start }

          # Update cache with cleaned data if it changed
          if cleaned_data != window_data
            if cleaned_data.empty?
              Rails.cache.delete(cache_key)
            else
              Rails.cache.write(cache_key, cleaned_data, expires_in: period + 60)
            end
          end

          current_count = cleaned_data.values.sum

          # Check if we're over the limit
          if current_count >= limit
            # Calculate retry after time with exponential backoff if configured
            retry_after = calculate_retry_after(cache_key, config, current_count, limit)

            reset_time = if cleaned_data.empty?
              Time.at(now + period)
            else
              Time.at(cleaned_data.keys.map(&:to_i).min + period)
            end

            {
              allowed: false,
              count: current_count,
              limit: limit,
              reset_time: reset_time,
              retry_after: retry_after,
              reason: "rate_limit_exceeded"
            }
          else
            {
              allowed: true,
              count: current_count,
              limit: limit,
              remaining: limit - current_count
            }
          end
        end

        def record_attempt(ip_address, result, user)
          return if result == :check # Don't record check operations

          now = Time.current.to_i

          # Record IP attempt
          ip_cache_key = "beskar:ip_attempts:#{ip_address}"
          record_attempt_in_cache(ip_cache_key, now)

          # Record account attempt if user exists
          if user
            account_cache_key = "beskar:account_attempts:#{user.class.name}:#{user.id}"
            record_attempt_in_cache(account_cache_key, now)
          end

          # Record global attempt
          global_cache_key = "beskar:global_attempts"
          record_attempt_in_cache(global_cache_key, now, 1.minute)
        end

        def record_attempt_in_cache(cache_key, timestamp, expiry = 1.hour)
          window_data = Rails.cache.read(cache_key) || {}
          window_data[timestamp] = (window_data[timestamp] || 0) + 1
          Rails.cache.write(cache_key, window_data, expires_in: expiry + 60)
        end

        def calculate_retry_after(cache_key, config, current_count, limit)
          return 0 unless config[:exponential_backoff]

          backoff_key = cache_key.gsub("_attempts:", "_backoff:")
          failure_count = Rails.cache.read(backoff_key) || 0

          # Increment failure count
          Rails.cache.write(backoff_key, failure_count + 1, expires_in: 1.hour)

          # Exponential backoff: 1min, 5min, 15min, 1hour, 4hours, 24hours
          base_delays = [60, 300, 900, 3600, 14400, 86400] # in seconds
          delay_index = [failure_count, base_delays.length - 1].min

          base_delays[delay_index]
        end

        def most_restrictive_result(results)
          # Find the most restrictive (not allowed) result
          restricted = results.find { |r| !r[:allowed] }
          return restricted if restricted

          # If all are allowed, return the one with the lowest remaining count
          results.min_by { |r| r[:remaining] || Float::INFINITY }
        end
      end

      # Instance methods for more complex scenarios
      def initialize(ip_address, user = nil)
        @ip_address = ip_address
        @user = user
      end

      def allowed?
        self.class.check_ip_rate_limit(@ip_address)[:allowed] &&
          (@user.nil? || self.class.check_account_rate_limit(@user)[:allowed])
      end

      def attempts_remaining
        ip_result = self.class.check_ip_rate_limit(@ip_address)
        account_result = @user ? self.class.check_account_rate_limit(@user) : {remaining: Float::INFINITY}

        [ip_result[:remaining] || 0, account_result[:remaining] || 0].min
      end

      def time_until_reset
        ip_result = self.class.check_ip_rate_limit(@ip_address)
        account_result = @user ? self.class.check_account_rate_limit(@user) : {retry_after: 0}

        [ip_result[:retry_after] || 0, account_result[:retry_after] || 0].max
      end

      def reset!
        self.class.reset_rate_limit(ip_address: @ip_address, user: @user)
      end

      # Sliding window analysis for pattern detection
      def suspicious_pattern?
        return false unless @user

        # Check for rapid-fire attempts
        recent_events = @user.security_events
          .login_failures
          .recent(5.minutes.ago)
          .order(:created_at)

        return true if recent_events.count >= 3

        # Check for distributed attack (same user, different IPs)
        if recent_events.count >= 2
          unique_ips = recent_events.pluck(:ip_address).uniq
          return true if unique_ips.length >= 2
        end

        false
      end

      def attack_pattern_type
        return :none unless suspicious_pattern?

        recent_events = @user.security_events.login_failures.recent(5.minutes.ago)
        unique_ips = recent_events.pluck(:ip_address).uniq
        unique_emails = recent_events.map(&:attempted_email).compact.uniq

        if unique_ips.length >= 2 && unique_emails.length == 1
          :distributed_single_account
        elsif unique_ips.length == 1 && unique_emails.length >= 3
          :single_ip_multiple_accounts
        elsif unique_ips.length == 1 && unique_emails.length == 1
          :brute_force_single_account
        else
          :mixed_attack_pattern
        end
      end
    end
  end
end
