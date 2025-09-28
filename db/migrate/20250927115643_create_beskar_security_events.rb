class CreateBeskarSecurityEvents < ActiveRecord::Migration[8.0]
  def change
    create_table :beskar_security_events do |t|
      t.references :user, polymorphic: true, null: false
      t.string :event_type
      t.string :ip_address
      t.text :user_agent
      t.json :metadata, default: {}
      t.integer :risk_score

      t.timestamps
    end
  end
end
