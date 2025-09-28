module Beskar
  class SecurityEvent < ApplicationRecord
    belongs_to :user, polymorphic: true
  end
end
