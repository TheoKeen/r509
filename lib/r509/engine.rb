require 'singleton'
require 'openssl'

module R509
  # a singleton class to store loaded OpenSSL Engines
  class Engine
    include Singleton

    def initialize
      @engines = {}
    end

    # @param hash Takes a hash with SO_PATH and ID
    # @return OpenSSL::Engine object
    def load(hash)
      validate_hash(hash)
      if @engines.key?(hash[:id])
        @engines[hash[:id]]
      else
        init_engine(hash)
      end
    end

    # Takes an engine ID and returns the engine object
    def [](key)
      @engines[key]
    end

    private

    def init_engine(hash)
      OpenSSL::Engine.load
      @engines[hash[:id]] = OpenSSL::Engine.by_id("dynamic") do |e|
        e.ctrl_cmd("SO_PATH", hash[:so_path])
        e.ctrl_cmd("ID", hash[:id])
        e.ctrl_cmd("LIST_ADD","1")
        e.ctrl_cmd("LOAD")
        e.ctrl_cmd("PIN", hash[:pin])
        e.ctrl_cmd("MODULE_PATH", hash[:module_path])
      end
    end

    def validate_hash(hash)
      return unless !hash.respond_to?(:key?) || !hash.key?(:so_path) || !hash.key?(:id)
      raise ArgumentError, "You must supply a hash with both :so_path and :id"
    end
  end
end
