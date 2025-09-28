require "beskar/version"
require "beskar/configuration"
require "beskar/middleware"
require "beskar/middleware/request_analyzer"
require "beskar/engine"

module Beskar
  class << self
    attr_accessor :configuration
  end

  def self.configure
    self.configuration ||= Configuration.new
    yield(configuration)
  end
end
