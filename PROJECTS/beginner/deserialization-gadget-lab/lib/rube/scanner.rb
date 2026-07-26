# ©AngelaMos | 2026
# scanner.rb

module Rube
  class Scanner
    GATED_METHODS = %w[marshal_load _load_data].freeze
    GATED_SINGLETON_METHODS = %w[_load].freeze
    UNGATED_METHODS = %w[hash eql? == <=> []= to_s method_missing respond_to_missing? coerce].freeze

    GATE_GATED = :gated
    GATE_UNGATED = :ungated

    PRISM_AVAILABLE = begin
      require "prism"
      true
    rescue LoadError
      false
    end

    LOCATION_SEPARATOR = ":"
    UNKNOWN_LOCATION = nil

    class Candidate
      attr_reader :class_name, :method_name, :gate, :source_location, :arity

      def initialize(class_name:, method_name:, gate:, source_location:, arity:, singleton:, touches_state:)
        @class_name = class_name
        @method_name = method_name
        @gate = gate
        @source_location = source_location
        @arity = arity
        @singleton = singleton
        @touches_state = touches_state
      end

      def singleton?
        @singleton
      end

      def gated?
        gate == GATE_GATED
      end

      def zero_arity?
        arity.zero?
      end

      def touches_state?
        @touches_state
      end

      def reachable?
        return true if gated?

        zero_arity? && touches_state?
      end

      def to_s
        "#{class_name}#{singleton? ? '.' : '#'}#{method_name}"
      end
    end

    class Report
      attr_reader :candidates, :scanned_modules

      def initialize(candidates, scanned_modules)
        @candidates = candidates
        @scanned_modules = scanned_modules
      end

      def gated
        candidates.select(&:gated?)
      end

      def ungated
        candidates.reject(&:gated?)
      end

      def reachable
        candidates.select(&:reachable?)
      end
    end

    def initialize(namespace: nil)
      @namespace = namespace
      @candidates = []
      @definition_cache = {}
      @scanned_modules = 0
    end

    def scan
      each_named_module do |mod, name|
        @scanned_modules += 1
        collect_instance_methods(mod, name)
        collect_singleton_methods(mod, name)
      end

      Report.new(@candidates.sort_by(&:to_s), @scanned_modules)
    end

    private

    attr_reader :namespace

    def each_named_module
      ObjectSpace.each_object(Module) do |mod|
        name = safe_name(mod)
        next unless name
        next unless in_namespace?(name)

        yield mod, name
      end
    end

    def safe_name(mod)
      name = mod.name
      name if name.is_a?(String) && !name.empty?
    rescue StandardError
      nil
    end

    def in_namespace?(name)
      namespace.nil? || name == namespace || name.start_with?("#{namespace}::")
    end

    def collect_instance_methods(mod, name)
      own = own_instance_methods(mod)

      (own & GATED_METHODS).each do |method_name|
        record(mod, name, method_name, GATE_GATED, singleton: false)
      end

      (own & UNGATED_METHODS).each do |method_name|
        record(mod, name, method_name, GATE_UNGATED, singleton: false)
      end
    end

    def collect_singleton_methods(mod, name)
      own = mod.singleton_methods(false).map(&:to_s)

      (own & GATED_SINGLETON_METHODS).each do |method_name|
        record(mod, name, method_name, GATE_GATED, singleton: true)
      end
    end

    def own_instance_methods(mod)
      (mod.instance_methods(false) + mod.private_instance_methods(false)).map(&:to_s)
    rescue StandardError
      []
    end

    def record(mod, name, method_name, gate, singleton:)
      handle = singleton ? mod.singleton_method(method_name) : mod.instance_method(method_name)

      @candidates << Candidate.new(
        class_name: name,
        method_name: method_name,
        gate: gate,
        source_location: format_location(handle.source_location),
        arity: handle.arity,
        singleton: singleton,
        touches_state: touches_state?(handle)
      )
    rescue StandardError, ScriptError
      nil
    end

    def format_location(location)
      return UNKNOWN_LOCATION unless location

      location.join(LOCATION_SEPARATOR)
    end

    def touches_state?(handle)
      return false unless PRISM_AVAILABLE

      path, line = handle.source_location
      return false unless path && line

      node = definition_at(path, line)
      return false unless node

      node.compact_child_nodes.any? { |child| state_reference?(child) }
    rescue StandardError, ScriptError
      false
    end

    def definition_at(path, line)
      definitions_for(path)[line]
    end

    def definitions_for(path)
      @definition_cache[path] ||= begin
        found = {}
        collect_definitions(Prism.parse_file(path).value, found)
        found
      rescue StandardError, ScriptError
        {}
      end
    end

    def collect_definitions(node, found)
      return unless node.is_a?(Prism::Node)

      found[node.location.start_line] = node if node.is_a?(Prism::DefNode)
      node.compact_child_nodes.each { |child| collect_definitions(child, found) }
    end

    def state_reference?(node)
      return false unless node.is_a?(Prism::Node)
      return true if node.is_a?(Prism::InstanceVariableReadNode)
      return true if node.is_a?(Prism::CallNode) && node.receiver.nil?

      node.compact_child_nodes.any? { |child| state_reference?(child) }
    end
  end
end
