FactoryBot.define do
  factory :user do
    sequence(:email) { |n| "user#{n}@example.com" }
    password { "password123" }
    password_confirmation { "password123" }

    trait :admin do
      email { "admin@example.com" }
    end

    trait :with_security_events do
      after(:create) do |user|
        create_list(:security_event, 3, user: user)
      end
    end

    trait :with_failed_attempts do
      after(:create) do |user|
        create_list(:security_event, 2, :login_failure, user: user, created_at: 5.minutes.ago)
      end
    end

    trait :with_recent_success do
      after(:create) do |user|
        create(:security_event, :login_success, user: user, created_at: 1.hour.ago)
      end
    end
  end
end
