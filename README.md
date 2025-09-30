# Beskar

**Beskar** is a comprehensive, Rails-native security engine designed to provide multi-layered, proactive protection for modern web applications. It defends against common threats, bot activity, and account takeovers without requiring external dependencies, integrating seamlessly into your application as a natural extension of the framework.

## Features

-   **Devise Integration:** Seamless integration with Devise authentication for automatic login tracking and security analysis.
-   **Risk-Based Account Locking:** Automatically locks accounts when authentication risk scores exceed configurable thresholds, preventing compromised account access.
-   **Smart Rate Limiting:** Distributed rate limiting using Rails.cache with IP-based and account-based throttling with exponential backoff.
-   **Brute Force Detection:** Advanced pattern recognition to detect single account attacks vs credential stuffing attempts.
-   **Security Event Tracking:** Comprehensive logging of authentication events with risk scoring and metadata extraction.
-   **IP Geolocation:** MaxMind GeoLite2-City database integration for country/city location, coordinates, timezone, and enhanced risk scoring (configurable, database not included due to licensing).
-   **Geographic Anomaly Detection:** Haversine-based impossible travel detection and location-based risk assessment.
-   **Web Application Firewall (WAF):** Real-time protection against common attack vectors like SQL Injection (SQLi) and Cross-Site Scripting (XSS).
-   **Advanced Bot Detection:** Multi-layered defense using JavaScript challenges and invisible honeypots to filter out malicious bots while allowing legitimate ones.
-   **Modular Architecture:** Devise-specific code is isolated in separate services for maintainability and extensibility.
-   **Rails-Native Architecture:** Built as a mountable `Rails::Engine`, it leverages `ActiveJob` and `Rails.cache` for high performance and low overhead.
-   **Real-Time Dashboard (Coming Soon):** A mountable dashboard to visualize security events and monitor threats as they happen.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'beskar'
````

And then execute:

```bash
$ bundle install
```

Next, run the installation generator. This will copy the necessary migrations and create an initializer file.

```bash
$ rails g beskar:install
```

Finally, run the database migrations:

```bash
$ rails db:migrate
```

## Configuration

You can configure Beskar in the initializer file created by the installer:

```ruby
# config/initializers/beskar.rb
Beskar.configure do |config|
  # === Security Tracking ===
  # Controls what security events are tracked and analyzed
  config.security_tracking = {
    enabled: true,                    # Master switch - disables all tracking when false
    track_successful_logins: true,    # Track successful authentication events
    track_failed_logins: true,        # Track failed authentication attempts
    auto_analyze_patterns: true       # Enable automatic pattern analysis for threats
  }

  # === Rate Limiting ===
  config.rate_limiting = {
    ip_attempts: {
      limit: 10,                    # Max attempts per IP
      period: 1.hour,               # Time window
      exponential_backoff: true     # Enable exponential backoff
    },
    account_attempts: {
      limit: 5,                     # Max attempts per account
      period: 15.minutes,           # Time window
      exponential_backoff: true
    },
    global_attempts: {
      limit: 100,                   # System-wide limit
      period: 1.minute,
      exponential_backoff: false
    }
  }

  # === Web Application Firewall (WAF) ===
  # Enable or disable the WAF middleware. Defaults to false.
  config.enable_waf = true

  # === Risk-Based Account Locking ===
  # Automatically lock accounts when authentication risk score exceeds threshold
  config.risk_based_locking = {
    enabled: false,                    # Master switch for risk-based locking
    risk_threshold: 75,                # Lock account if risk score >= this value (0-100)
    lock_strategy: :devise_lockable,   # Strategy: :devise_lockable, :custom, :none
    auto_unlock_time: 1.hour,          # Time until automatic unlock (if supported)
    notify_user: true,                 # Send notification on lock (future feature)
    log_lock_events: true              # Create security event for locks
  }

  # === IP Geolocation ===
  # Configure IP geolocation for enhanced risk assessment
  # Note: You must provide your own MaxMind GeoLite2-City database due to licensing
  # Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
  config.geolocation = {
    provider: :maxmind,                # Provider: :maxmind or :mock (for testing)
    maxmind_city_db_path: Rails.root.join('db', 'geoip', 'GeoLite2-City.mmdb').to_s,
    cache_ttl: 4.hours                 # How long to cache geolocation results
  }
end

# Security Tracking Configuration Details
The security tracking system respects all configuration settings:

- **`enabled: false`** - Completely disables all security event tracking
- **`track_successful_logins: false`** - Stops tracking successful login events
- **`track_failed_logins: false`** - Stops tracking failed login attempts  
- **`auto_analyze_patterns: false`** - Disables automatic threat pattern analysis

When tracking is disabled via configuration, no `SecurityEvent` records are created and no background analysis jobs are queued.
```

## Usage

### Basic Setup

Once installed and configured, Beskar works automatically with Devise. Add the `SecurityTrackable` module to your User model:

```ruby
class User < ApplicationRecord
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable
  
  # Add Beskar security tracking
  include Beskar::Models::SecurityTrackable
end
```

### Risk-Based Account Locking (with Devise Lockable)

Beskar can automatically lock user accounts when the calculated risk score exceeds a configured threshold. This prevents compromised accounts from being accessed even after successful authentication.

**Setup with Devise Lockable:**

1. Enable the `:lockable` module in your User model:

```ruby
class User < ApplicationRecord
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable,
         :lockable  # Add this for risk-based locking
  
  include Beskar::Models::SecurityTrackable
end
```

2. Generate and run the migration to add lockable columns:

```bash
rails generate devise User  # This will add lockable columns if not present
# Or manually add:
# - failed_attempts (integer)
# - unlock_token (string)
# - locked_at (datetime)
rails db:migrate
```

3. Enable risk-based locking in your initializer:

```ruby
# config/initializers/beskar.rb
Beskar.configure do |config|
  config.risk_based_locking = {
    enabled: true,                     # Enable the feature
    risk_threshold: 75,                # Lock when risk >= 75
    lock_strategy: :devise_lockable,   # Use Devise's lockable module
    auto_unlock_time: 1.hour,          # Automatic unlock after 1 hour
    notify_user: true,                 # Log notification intent
    log_lock_events: true              # Create security events
  }
end
```

**How it works:**

- After each successful authentication, Beskar calculates a risk score (0-100) based on:
  - Geographic anomalies (impossible travel, country changes)
  - Device fingerprints (suspicious user agents, bot signatures)
  - Login patterns (velocity, time of day, recent failures)
  - IP reputation and geolocation risk

- **Adaptive Learning:** The system learns from user behavior:
  - After 2+ successful logins from an IP, that location becomes "established"
  - If a user unlocks and logs in successfully, that pattern is trusted
  - Risk scores are reduced to 30% for established patterns (capped at 25)
  - This prevents repeated locks after users validate their login context

- If the risk score meets or exceeds the configured threshold, the account is automatically locked
- The user session is terminated immediately to prevent access
- A security event is logged with the lock reason and risk details (always logged for audit trail)
- The account remains locked until manually unlocked or the auto-unlock time expires (if supported)

**Example Adaptive Flow:**
1. User travels to new location → High risk (85) → Account locked
2. User unlocks account → Validates legitimacy
3. User logs in from same location → Pattern established → Risk reduced to 25 → Login succeeds ✅
4. Future logins from this location → Normal risk → No more locks

See `ADAPTIVE_LEARNING.md` for detailed documentation.

**Lock Reasons:**

The system identifies specific reasons for locking:
- `:impossible_travel` - Login from location requiring impossible travel speed
- `:suspicious_device` - Bot signature or suspicious user agent detected
- `:geographic_anomaly` - Country change or high-risk location
- `:high_risk_authentication` - General high-risk authentication pattern

**Manual Lock/Unlock Operations:**

```ruby
# Manually lock an account based on risk
locker = Beskar::Services::AccountLocker.new(
  user,
  risk_score: 85,
  reason: :suspicious_device,
  metadata: { ip_address: request.ip }
)

if locker.should_lock?
  locker.lock!  # Lock the account
end

# Check if account is locked
locker.locked?  # => true/false

# Manually unlock
locker.unlock!
```

### Security Event Tracking

Beskar automatically tracks login attempts and creates security events with rich metadata:

```ruby
# Check recent failed attempts for a user
user.recent_failed_attempts(within: 1.hour)

# Check if user has suspicious login patterns
user.suspicious_login_pattern?

# Get recent successful logins
user.recent_successful_logins(within: 24.hours)

# Access security events
user.security_events.login_failures.recent
```

### Rate Limiting

Check if a request should be rate limited:

```ruby
# In a controller or middleware
if Beskar.rate_limited?(request, current_user)
  render json: { error: 'Rate limit exceeded' }, status: 429
  return
end

# Manual rate limiting check
rate_limiter = Beskar::Services::RateLimiter.new(request.ip, current_user)
unless rate_limiter.allowed?
  # Handle rate limiting
  time_until_reset = rate_limiter.time_until_reset
end
```

### Security Events Analysis

Security events are automatically created and include:

- **Event Type**: `login_success`, `login_failure`
- **IP Address**: Client IP with proxy detection
- **User Agent**: Browser and device information
- **Risk Score**: 0-100 based on various factors
- **Metadata**: Device info, geolocation, timestamps
- **Attack Patterns**: Detection of brute force, credential stuffing, etc.

### Attack Pattern Detection

Beskar can identify different types of attacks:

```ruby
rate_limiter = Beskar::Services::RateLimiter.new(ip_address, user)
attack_type = rate_limiter.attack_pattern_type

case attack_type
when :brute_force_single_account
  # Single IP attacking one account
when :distributed_single_account  
  # Multiple IPs attacking one account
when :single_ip_multiple_accounts
  # One IP attacking multiple accounts (credential stuffing)
when :mixed_attack_pattern
  # Complex attack pattern
end
```

### Middleware Integration

Beskar automatically injects its middleware into the Rails stack to:

- Track authentication events via Warden callbacks
- Analyze request patterns for suspicious activity
- Apply rate limiting before requests reach your controllers
- Log security events for analysis

Security events are logged to the `beskar_security_events` table for analysis and will be visualized in the forthcoming security dashboard.

## Development

After checking out the repo, run `bundle install` to install dependencies. The gem contains a dummy Rails application in `test/dummy` for development and testing.

To run the test suite, use the standard Rails command:

```bash
# From the gem's root directory
$ bin/rails test
```

## Contributing

Bug reports and pull requests are welcome on GitHub at [https://github.com/prograis/beskar](https://github.com/prograils/beskar). 

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Just be nice to each other.

