# WAF Monitor-Only Mode

## Overview

Monitor-only mode allows you to enable the Web Application Firewall (WAF) to detect and log vulnerability scanning attempts **without actually blocking any requests**. This is ideal for:

- **Testing WAF in production** without risking false positives blocking legitimate users
- **Analyzing attack patterns** before enabling blocking
- **Gathering data** to tune your block threshold settings
- **Gradual rollout** of WAF protection

## Configuration

```ruby
# config/initializers/beskar.rb
Beskar.configure do |config|
  config.waf = {
    enabled: true,              # Enable WAF detection
    monitor_only: true,         # ⚠️ Log violations but DON'T block
    auto_block: true,           # This will be honored when monitor_only is false
    block_threshold: 3,         # Track threshold for reporting
    violation_window: 1.hour,
    create_security_events: true
  }
end
```

## What Gets Logged

### 1. Every Violation (with Mode Indicator)

```
[Beskar::WAF] 🚨 Vulnerability scan detected [MONITOR-ONLY MODE] 
(3 violations) - IP: 203.0.113.50, Severity: critical, 
Patterns: Configuration file access attempt, Path: /.env
```

The `[MONITOR-ONLY MODE]` tag appears on every violation log so you can easily identify them.

### 2. Explicit "Would Block" Messages

When violation count reaches the threshold, you'll see:

```
[Beskar::WAF] 🔍 MONITOR-ONLY: IP 203.0.113.50 WOULD BE BLOCKED 
(threshold reached: 3/3 violations) - Duration would be: 1.0 hours, 
Severity: critical, Patterns: Configuration file access attempt. 
To enable blocking, set config.waf[:monitor_only] = false
```

### 3. Middleware-Level Logging

The middleware also explicitly logs when it would have blocked:

```
[Beskar::Middleware] 🔍 MONITOR-ONLY: Would block IP 203.0.113.50 
after 3 WAF violations, but monitor_only=true. Request proceeding normally.
```

## Security Event Metadata

All WAF violations in monitor-only mode include rich metadata for analysis:

```ruby
event = Beskar::SecurityEvent.where(event_type: 'waf_violation').last

event.metadata
# => {
#   "monitor_only_mode" => true,
#   "would_be_blocked" => true,          # Would this have been blocked?
#   "violation_count" => 3,
#   "block_threshold" => 3,
#   "severity" => "critical",
#   "patterns_matched" => ["Configuration file access attempt"],
#   "waf_analysis" => { ... }
# }
```

## Analyzing Monitor-Only Data

### Query IPs that would have been blocked:

```ruby
# Find all IPs that would have been blocked
would_be_blocked = Beskar::SecurityEvent
  .where(event_type: 'waf_violation')
  .where("metadata->>'monitor_only_mode' = ?", 'true')
  .where("metadata->>'would_be_blocked' = ?", 'true')
  .group(:ip_address)
  .count

puts "IPs that would be blocked: #{would_be_blocked}"
# => {"203.0.113.50"=>5, "198.51.100.42"=>3}
```

### Analyze attack patterns:

```ruby
# Most common attack patterns detected
patterns = Beskar::SecurityEvent
  .where(event_type: 'waf_violation')
  .where("created_at > ?", 24.hours.ago)
  .pluck(:metadata)
  .flat_map { |m| m['patterns_matched'] }
  .tally
  .sort_by { |_, count| -count }

patterns.each do |pattern, count|
  puts "#{pattern}: #{count} attempts"
end
# => Configuration file access attempt: 45
#    WordPress vulnerability scan: 23
#    Path traversal attempt: 12
```

### Calculate blocking impact:

```ruby
# How many unique IPs would have been blocked?
blocked_ips = Beskar::SecurityEvent
  .where(event_type: 'waf_violation')
  .where("metadata->>'would_be_blocked' = ?", 'true')
  .distinct
  .pluck(:ip_address)

puts "#{blocked_ips.count} unique IPs would have been blocked"

# How many total requests would have been denied?
total_requests = Beskar::SecurityEvent
  .where(event_type: 'waf_violation', ip_address: blocked_ips)
  .where("created_at > ?", 24.hours.ago)
  .count

puts "#{total_requests} requests would have been blocked in the last 24h"
```

## Transitioning to Active Blocking

### Step 1: Monitor for 24-48 hours

```ruby
# Enable monitor-only mode
config.waf[:monitor_only] = true
```

### Step 2: Review the logs

Look for:
- False positives (legitimate traffic being flagged)
- Attack volume and patterns
- IPs that would have been blocked

### Step 3: Whitelist any false positives

```ruby
config.ip_whitelist = [
  "192.168.1.0/24",  # Office network
  "203.0.113.42"     # Partner API server
]
```

### Step 4: Enable blocking

```ruby
# Turn off monitor-only mode
config.waf[:monitor_only] = false
```

### Step 5: Continue monitoring

Watch for actual blocks:

```
[Beskar::WAF] 🔒 Auto-blocked IP 203.0.113.50 after 3 violations (duration: 1 hours)
[Beskar::Middleware] 🔒 Blocking IP 203.0.113.50 after 3 WAF violations
```

## Log Filtering

### View only monitor-only violations:

```bash
# Production logs
tail -f log/production.log | grep "MONITOR-ONLY"
```

### View all WAF activity:

```bash
tail -f log/production.log | grep "Beskar::WAF"
```

### View would-be blocks:

```bash
tail -f log/production.log | grep "WOULD BE BLOCKED"
```

## Best Practices

1. **Start with monitor-only** - Always enable monitor_only=true for at least 24 hours in production
2. **Review before blocking** - Analyze the data before turning on auto-blocking
3. **Set appropriate thresholds** - Adjust `block_threshold` based on your monitor-only data
4. **Whitelist proactively** - Add known-good IPs to the whitelist before enabling blocking
5. **Monitor actively** - Set up alerts for "WOULD BE BLOCKED" messages to understand impact
6. **Keep security events** - Don't delete old WAF events; they're valuable for trend analysis

## Example Workflow

```ruby
# Week 1: Monitor only
Beskar.configure do |config|
  config.waf = {
    enabled: true,
    monitor_only: true,
    block_threshold: 3
  }
end

# After reviewing logs and confirming no false positives...

# Week 2: Enable blocking with higher threshold
Beskar.configure do |config|
  config.waf = {
    enabled: true,
    monitor_only: false,  # ✅ Now actually blocking
    block_threshold: 5,   # Start conservative
    auto_block: true
  }
end

# Week 3: Tune threshold based on real blocking data
Beskar.configure do |config|
  config.waf = {
    enabled: true,
    monitor_only: false,
    block_threshold: 3,   # Tighten security
    auto_block: true
  }
end
```

## Troubleshooting

### Not seeing "MONITOR-ONLY" in logs?

Check your configuration:
```ruby
Beskar.configuration.waf_monitor_only?  # => should return true
```

### Not seeing "would_be_blocked" in metadata?

Ensure you're exceeding the threshold:
```ruby
Beskar::Services::Waf.get_violation_count("203.0.113.50")  # => should be >= threshold
```

### Security events not being created?

Check:
```ruby
Beskar.configuration.waf[:create_security_events]  # => should be true
```
