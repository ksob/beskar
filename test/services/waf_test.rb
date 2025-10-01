require "test_helper"

class WafTest < ActiveSupport::TestCase
  def setup
    Rails.cache.clear
    Beskar.configuration.waf = {
      enabled: true,
      auto_block: true,
      block_threshold: 3,
      violation_window: 1.hour,
      create_security_events: true
    }
  end

  def teardown
    Rails.cache.clear
    Beskar.configuration.waf = { enabled: false }
  end

  def create_mock_request(path, ip: "192.168.1.100", user_agent: "TestBot/1.0")
    mock_request = mock()
    mock_request.stubs(:fullpath).returns(path)
    mock_request.stubs(:path).returns(path.split('?').first)
    mock_request.stubs(:ip).returns(ip)
    mock_request.stubs(:user_agent).returns(user_agent)
    mock_request
  end

  # WordPress vulnerability scans
  test "analyze_request detects wp-admin access" do
    request = create_mock_request("/wp-admin/index.php")
    result = Beskar::Services::Waf.analyze_request(request)
    
    assert_not_nil result
    assert result[:threat_detected]
    assert_equal 1, result[:patterns].length
    assert_equal :wordpress, result[:patterns].first[:category]
    assert_equal :high, result[:highest_severity]
  end

  test "analyze_request detects wp-login.php" do
    request = create_mock_request("/wp-login.php")
    result = Beskar::Services::Waf.analyze_request(request)
    
    assert_not_nil result
    assert result[:threat_detected]
    assert_includes result[:patterns].map { |p| p[:category] }, :wordpress
  end

  test "analyze_request detects xmlrpc.php" do
    request = create_mock_request("/xmlrpc.php")
    result = Beskar::Services::Waf.analyze_request(request)
    
    assert_not_nil result
    assert result[:threat_detected]
  end

  # PHP admin panel scans
  test "analyze_request detects phpmyadmin access" do
    request = create_mock_request("/phpmyadmin/")
    result = Beskar::Services::Waf.analyze_request(request)
    
    assert_not_nil result
    assert result[:threat_detected]
    assert_equal :php_admin, result[:patterns].first[:category]
  end

  test "analyze_request detects admin.php" do
    request = create_mock_request("/admin.php")
    result = Beskar::Services::Waf.analyze_request(request)
    
    assert_not_nil result
    assert result[:threat_detected]
  end

  # Configuration file access
  test "analyze_request detects .env file access" do
    request = create_mock_request("/.env")
    result = Beskar::Services::Waf.analyze_request(request)
    
    assert_not_nil result
    assert result[:threat_detected]
    assert_equal :config_files, result[:patterns].first[:category]
    assert_equal :critical, result[:highest_severity]
  end

  test "analyze_request detects .git directory access" do
    request = create_mock_request("/.git/config")
    result = Beskar::Services::Waf.analyze_request(request)
    
    assert_not_nil result
    assert result[:threat_detected]
    assert_equal :critical, result[:highest_severity]
  end

  test "analyze_request detects config.php" do
    request = create_mock_request("/config.php")
    result = Beskar::Services::Waf.analyze_request(request)
    
    assert_not_nil result
    assert result[:threat_detected]
  end

  # Path traversal attempts
  test "analyze_request detects /etc/passwd access" do
    request = create_mock_request("/etc/passwd")
    result = Beskar::Services::Waf.analyze_request(request)
    
    assert_not_nil result
    assert result[:threat_detected]
    assert_equal :path_traversal, result[:patterns].first[:category]
    assert_equal :critical, result[:highest_severity]
  end

  test "analyze_request detects ../ path traversal" do
    request = create_mock_request("/files/../../etc/passwd")
    result = Beskar::Services::Waf.analyze_request(request)
    
    assert_not_nil result
    assert result[:threat_detected]
    assert_equal :path_traversal, result[:patterns].first[:category]
  end

  test "analyze_request detects URL encoded path traversal" do
    request = create_mock_request("/files/%2e%2e/etc/passwd")
    result = Beskar::Services::Waf.analyze_request(request)
    
    assert_not_nil result
    assert result[:threat_detected]
  end

  # Framework debug endpoints
  test "analyze_request detects Rails debug routes" do
    request = create_mock_request("/rails/info/routes")
    result = Beskar::Services::Waf.analyze_request(request)
    
    assert_not_nil result
    assert result[:threat_detected]
    assert_equal :framework_debug, result[:patterns].first[:category]
  end

  test "analyze_request detects __debug__ endpoint" do
    request = create_mock_request("/__debug__/")
    result = Beskar::Services::Waf.analyze_request(request)
    
    assert_not_nil result
    assert result[:threat_detected]
  end

  # Common exploits
  test "analyze_request detects shell.php" do
    request = create_mock_request("/shell.php")
    result = Beskar::Services::Waf.analyze_request(request)
    
    assert_not_nil result
    assert result[:threat_detected]
    assert_equal :common_exploits, result[:patterns].first[:category]
    assert_equal :critical, result[:highest_severity]
  end

  test "analyze_request detects c99.php" do
    request = create_mock_request("/c99.php")
    result = Beskar::Services::Waf.analyze_request(request)
    
    assert_not_nil result
    assert result[:threat_detected]
  end

  # Legitimate paths should not trigger
  test "analyze_request allows legitimate paths" do
    legitimate_paths = [
      "/",
      "/users",
      "/posts/123",
      "/api/v1/data",
      "/about",
      "/contact"
    ]
    
    legitimate_paths.each do |path|
      request = create_mock_request(path)
      result = Beskar::Services::Waf.analyze_request(request)
      
      assert_nil result, "Path #{path} should not trigger WAF"
    end
  end

  test "analyze_request returns nil for blank paths" do
    request = create_mock_request("")
    result = Beskar::Services::Waf.analyze_request(request)
    
    assert_nil result
  end

  # Violation tracking
  test "record_violation increments violation count" do
    ip = "10.0.0.100"
    request = create_mock_request("/wp-admin/", ip: ip)
    analysis = Beskar::Services::Waf.analyze_request(request)
    
    count1 = Beskar::Services::Waf.record_violation(ip, analysis)
    assert_equal 1, count1
    
    count2 = Beskar::Services::Waf.record_violation(ip, analysis)
    assert_equal 2, count2
    
    count3 = Beskar::Services::Waf.record_violation(ip, analysis)
    assert_equal 3, count3
  end

  test "get_violation_count returns current count" do
    ip = "10.0.0.101"
    
    assert_equal 0, Beskar::Services::Waf.get_violation_count(ip)
    
    Rails.cache.write("beskar:waf_violations:#{ip}", 5, expires_in: 1.hour)
    
    assert_equal 5, Beskar::Services::Waf.get_violation_count(ip)
  end

  test "reset_violations clears count" do
    ip = "10.0.0.102"
    Rails.cache.write("beskar:waf_violations:#{ip}", 10, expires_in: 1.hour)
    
    assert_equal 10, Beskar::Services::Waf.get_violation_count(ip)
    
    Beskar::Services::Waf.reset_violations(ip)
    
    assert_equal 0, Beskar::Services::Waf.get_violation_count(ip)
  end

  # Auto-blocking
  test "should_block? returns false when violations below threshold" do
    ip = "10.0.0.103"
    Rails.cache.write("beskar:waf_violations:#{ip}", 2, expires_in: 1.hour)
    
    assert_equal false, Beskar::Services::Waf.should_block?(ip)
  end

  test "should_block? returns true when violations meet threshold" do
    ip = "10.0.0.104"
    Rails.cache.write("beskar:waf_violations:#{ip}", 3, expires_in: 1.hour)
    
    assert Beskar::Services::Waf.should_block?(ip)
  end

  test "should_block? returns true when violations exceed threshold" do
    ip = "10.0.0.105"
    Rails.cache.write("beskar:waf_violations:#{ip}", 5, expires_in: 1.hour)
    
    assert Beskar::Services::Waf.should_block?(ip)
  end

  test "should_block? returns false when WAF disabled" do
    Beskar.configuration.waf[:enabled] = false
    ip = "10.0.0.106"
    Rails.cache.write("beskar:waf_violations:#{ip}", 10, expires_in: 1.hour)
    
    assert_equal false, Beskar::Services::Waf.should_block?(ip)
  end

  test "should_block? returns false when auto_block disabled" do
    Beskar.configuration.waf[:auto_block] = false
    ip = "10.0.0.107"
    Rails.cache.write("beskar:waf_violations:#{ip}", 10, expires_in: 1.hour)
    
    assert_equal false, Beskar::Services::Waf.should_block?(ip)
  end

  # Security event creation
  test "record_violation creates security event when configured" do
    Beskar.configuration.waf[:create_security_events] = true
    
    ip = "10.0.0.108"
    request = create_mock_request("/wp-admin/", ip: ip)
    analysis = Beskar::Services::Waf.analyze_request(request)
    
    assert_difference 'Beskar::SecurityEvent.count', 1 do
      Beskar::Services::Waf.record_violation(ip, analysis)
    end
    
    event = Beskar::SecurityEvent.last
    assert_equal 'waf_violation', event.event_type
    assert_equal ip, event.ip_address
    assert event.risk_score >= 80 # high severity
  end

  test "record_violation does not create security event when disabled" do
    Beskar.configuration.waf[:create_security_events] = false
    
    ip = "10.0.0.109"
    request = create_mock_request("/wp-admin/", ip: ip)
    analysis = Beskar::Services::Waf.analyze_request(request)
    
    assert_no_difference 'Beskar::SecurityEvent.count' do
      Beskar::Services::Waf.record_violation(ip, analysis)
    end
  end

  # Auto-blocking on threshold
  test "record_violation auto-blocks IP after threshold violations" do
    Beskar.configuration.waf[:auto_block] = true
    Beskar.configuration.waf[:block_threshold] = 3
    
    ip = "10.0.0.110"
    request = create_mock_request("/wp-admin/", ip: ip)
    analysis = Beskar::Services::Waf.analyze_request(request)
    
    # First two violations should not block
    Beskar::Services::Waf.record_violation(ip, analysis)
    Beskar::Services::Waf.record_violation(ip, analysis)
    assert_equal false, Beskar::BannedIp.banned?(ip)
    
    # Third violation should trigger block
    assert_difference 'Beskar::BannedIp.count', 1 do
      Beskar::Services::Waf.record_violation(ip, analysis)
    end
    
    assert Beskar::BannedIp.banned?(ip)
    
    banned_ip = Beskar::BannedIp.find_by(ip_address: ip)
    assert_equal 'waf_violation', banned_ip.reason
  end

  # Case sensitivity
  test "analyze_request is case insensitive for patterns" do
    paths = [
      "/WP-ADMIN/index.php",
      "/Wp-Admin/index.php",
      "/wp-ADMIN/index.php"
    ]
    
    paths.each do |path|
      request = create_mock_request(path)
      result = Beskar::Services::Waf.analyze_request(request)
      
      assert_not_nil result, "Path #{path} should trigger WAF"
      assert result[:threat_detected]
    end
  end

  # Multiple pattern matching
  test "analyze_request detects multiple patterns in single request" do
    # This path might match both wordpress and path_traversal
    request = create_mock_request("/wp-admin/../../etc/passwd")
    result = Beskar::Services::Waf.analyze_request(request)
    
    assert_not_nil result
    assert result[:threat_detected]
    assert result[:patterns].length >= 1
  end

  # Severity calculation
  test "highest_severity returns critical when critical pattern detected" do
    request = create_mock_request("/.env")
    result = Beskar::Services::Waf.analyze_request(request)
    
    assert_equal :critical, result[:highest_severity]
  end

  test "highest_severity returns high when only high patterns detected" do
    request = create_mock_request("/wp-admin/")
    result = Beskar::Services::Waf.analyze_request(request)
    
    assert_equal :high, result[:highest_severity]
  end

  test "highest_severity returns medium when only medium patterns detected" do
    request = create_mock_request("/rails/info/routes")
    result = Beskar::Services::Waf.analyze_request(request)
    
    assert_equal :medium, result[:highest_severity]
  end

  # Violation window expiry
  test "violations expire after violation_window" do
    Beskar.configuration.waf[:violation_window] = 0.1.seconds
    
    ip = "10.0.0.111"
    request = create_mock_request("/wp-admin/", ip: ip)
    analysis = Beskar::Services::Waf.analyze_request(request)
    
    Beskar::Services::Waf.record_violation(ip, analysis)
    assert_equal 1, Beskar::Services::Waf.get_violation_count(ip)
    
    sleep(0.2) # Wait for violation window to expire
    
    # Cache should have expired
    assert_equal 0, Beskar::Services::Waf.get_violation_count(ip)
  end
end
