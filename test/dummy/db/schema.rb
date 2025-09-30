# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.0].define(version: 2025_09_29_092712) do
  create_table "beskar_security_events", force: :cascade do |t|
    t.string "user_type"
    t.integer "user_id"
    t.string "event_type"
    t.string "ip_address"
    t.text "user_agent"
    t.json "metadata", default: {}
    t.integer "risk_score"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.string "attempted_email"
    t.index ["attempted_email"], name: "index_beskar_security_events_on_attempted_email"
    t.index ["created_at"], name: "index_beskar_security_events_on_created_at"
    t.index ["event_type"], name: "index_beskar_security_events_on_event_type"
    t.index ["ip_address", "event_type", "created_at"], name: "index_security_events_on_ip_event_time"
    t.index ["ip_address"], name: "index_beskar_security_events_on_ip_address"
    t.index ["risk_score"], name: "index_beskar_security_events_on_risk_score"
    t.index ["user_type", "user_id"], name: "index_beskar_security_events_on_user"
    t.index ["user_type", "user_id"], name: "index_beskar_security_events_on_user_type_and_user_id"
  end

  create_table "users", force: :cascade do |t|
    t.string "email", default: "", null: false
    t.string "encrypted_password", default: "", null: false
    t.string "reset_password_token"
    t.datetime "reset_password_sent_at"
    t.datetime "remember_created_at"
    t.integer "sign_in_count", default: 0, null: false
    t.datetime "current_sign_in_at"
    t.datetime "last_sign_in_at"
    t.string "current_sign_in_ip"
    t.string "last_sign_in_ip"
    t.string "confirmation_token"
    t.datetime "confirmed_at"
    t.datetime "confirmation_sent_at"
    t.string "unconfirmed_email"
    t.integer "failed_attempts", default: 0, null: false
    t.string "unlock_token"
    t.datetime "locked_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["email"], name: "index_users_on_email", unique: true
    t.index ["reset_password_token"], name: "index_users_on_reset_password_token", unique: true
  end
end
