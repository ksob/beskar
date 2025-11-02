module Beskar
  class ApplicationController < ActionController::Base
    # Use the main app's CSRF protection settings
    protect_from_forgery with: :exception, prepend: true

    layout 'beskar/application'

    # Ensure CSRF token is available for forms
    before_action :ensure_csrf_token

    before_action :authenticate_admin!

    private

    # Override this method in your application to implement authentication
    # For example, you might want to use Devise's authenticate_admin! or
    # a custom authentication method
    def authenticate_admin!
      # If custom authentication is configured, use it
      if Beskar.configuration.authenticate_admin.present?
        begin
          result = Beskar.configuration.authenticate_admin.call(request)
          unless result
            handle_authentication_failure
            return false
          end
        rescue => e
          Rails.logger.error "Beskar authentication error: #{e.message}"
          handle_authentication_failure
          return false
        end
      else
        # Default behavior: allow in development, require configuration in production
        if Rails.env.production?
          render plain: "Authentication required. Configure Beskar.configuration.authenticate_admin in your initializer.", status: :unauthorized
          return false
        elsif Rails.env.test?
          # Allow access in test environment
          return true
        else
          # Development mode - show a warning but allow access
          Rails.logger.warn "Beskar dashboard accessed without authentication configuration (development mode)"
          return true
        end
      end
    end

    def handle_authentication_failure
      respond_to do |format|
        format.html {
          render plain: "Unauthorized access to Beskar dashboard", status: :unauthorized
        }
        format.json { render json: { error: "Unauthorized" }, status: :unauthorized }
      end
    end

    # Helper method to format timestamps
    def format_timestamp(time)
      return "-" unless time
      time.in_time_zone.strftime("%Y-%m-%d %H:%M:%S %Z")
    end
    helper_method :format_timestamp

    # Helper method to format IP addresses with location if available
    def format_ip_with_location(ip, metadata = {})
      return ip unless metadata.present?

      location_parts = []
      if metadata["geolocation"].present?
        geo = metadata["geolocation"]
        location_parts << geo["city"] if geo["city"].present?
        location_parts << geo["country"] if geo["country"].present?
      end

      return ip if location_parts.empty?
      "#{ip} (#{location_parts.join(', ')})"
    end
    helper_method :format_ip_with_location

    # Helper to determine risk level badge color
    def risk_level_class(risk_score)
      return "neutral" unless risk_score

      case risk_score
      when 0..30
        "success"
      when 31..60
        "warning"
      when 61..85
        "danger"
      else
        "critical"
      end
    end
    helper_method :risk_level_class

    # Helper to format event type for display
    def format_event_type(event_type)
      event_type.to_s.humanize.titleize
    end
    helper_method :format_event_type

    # Pagination helper
    def paginate(collection, per_page: 25)
      # Handle per_page from params if provided
      if params[:per_page].present?
        per_page = params[:per_page].to_i
        per_page = 25 if per_page <= 0  # Default if invalid
        per_page = 100 if per_page > 100  # Max limit
      end

      page = (params[:page] || 1).to_i
      page = 1 if page < 1

      total_count = collection.count
      total_pages = total_count > 0 ? (total_count.to_f / per_page).ceil : 0

      offset = (page - 1) * per_page
      records = collection.limit(per_page).offset(offset)

      {
        records: records,
        current_page: page,
        total_pages: total_pages,
        total_count: total_count,
        per_page: per_page,
        has_previous: page > 1,
        has_next: page < total_pages,
        previous_page: page > 1 ? page - 1 : nil,
        next_page: page < total_pages ? page + 1 : nil
      }
    end

    # Ensure CSRF token is properly set for forms in the engine
    def ensure_csrf_token
      # Force generation of CSRF token if not present
      form_authenticity_token
    end
  end
end
