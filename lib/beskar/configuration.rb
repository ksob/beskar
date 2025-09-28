module Beskar
  class Configuration
    attr_accessor :enable_waf, :waf_ruleset, :user_class

    def initialize
      @enable_waf = false # Default to off
      @waf_ruleset = :default
      @user_class = "::User" # Default host app user class
    end
  end
end
