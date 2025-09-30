class AddAttemptedEmailToBeskarSecurityEvents < ActiveRecord::Migration[8.0]
  def change
    add_column :beskar_security_events, :attempted_email, :string
    add_index :beskar_security_events, :attempted_email
  end
end
