Beskar.configure do |config|
  # Enable geolocation with MaxMind City database (if available)
  # In CI/environments without the database, falls back to mock provider
  city_db_path = Rails.root.join('config', 'GeoLite2-City.mmdb').to_s
  
  config.geolocation = {
    provider: File.exist?(city_db_path) ? :maxmind : :mock,
    maxmind_city_db_path: File.exist?(city_db_path) ? city_db_path : nil,
    cache_ttl: 4.hours
  }
end
