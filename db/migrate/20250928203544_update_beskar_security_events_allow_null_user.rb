class UpdateBeskarSecurityEventsAllowNullUser < ActiveRecord::Migration[8.0]
  def change
    change_column_null :beskar_security_events, :user_id, true
    change_column_null :beskar_security_events, :user_type, true

    add_index :beskar_security_events, :ip_address
    add_index :beskar_security_events, :event_type
    add_index :beskar_security_events, :created_at
    add_index :beskar_security_events, [:user_type, :user_id]
    add_index :beskar_security_events, [:ip_address, :event_type, :created_at], name: 'index_security_events_on_ip_event_time'
    add_index :beskar_security_events, :risk_score
  end
end
