module Beskar
  class SecurityEvent < ApplicationRecord
    belongs_to :user, polymorphic: true, optional: true

    validates :event_type, presence: true
    validates :ip_address, presence: true
    validates :risk_score, numericality: {in: 0..100}

    scope :login_failures, -> { where(event_type: "login_failure") }
    scope :login_successes, -> { where(event_type: "login_success") }
    scope :recent, ->(time = 1.hour.ago) { where("created_at >= ?", time) }
    scope :by_ip, ->(ip) { where(ip_address: ip) }
    scope :high_risk, -> { where("risk_score >= ?", 70) }
    scope :critical_risk, -> { where("risk_score >= ?", 90) }

    def critical_threat?
      risk_score >= 90
    end

    def high_risk?
      risk_score >= 70
    end

    def login_failure?
      event_type == "login_failure"
    end

    def login_success?
      event_type == "login_success"
    end

    def attempted_email
      read_attribute(:attempted_email) || metadata&.dig("attempted_email")
    end

    def attempted_email=(value)
      write_attribute(:attempted_email, value)
      # Also store in metadata for backwards compatibility
      self.metadata = (metadata || {}).merge("attempted_email" => value) if value.present?
    end

    def device_info
      metadata&.dig("device_info") || {}
    end

    def geolocation
      metadata&.dig("geolocation") || {}
    end

    def details
      # Extract details from metadata if available
      # Check multiple possible fields where details might be stored
      return nil unless metadata.present?

      metadata["details"] ||
        metadata["description"] ||
        metadata["message"] ||
        metadata["reason"] ||
        metadata["error"] ||
        metadata["info"] ||
        nil
    end
  end
end
