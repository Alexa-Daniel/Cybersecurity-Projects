# ©AngelaMos | 2026
# scanner.rb
# frozen_string_literal: true

module Marshalsea
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

    STATE_UNREADABLE = :unreadable
    STATE_UNANALYSABLE = :unanalysable
    STATE_VERDICTS = [true, false].freeze

    SITE_MODULE_NAME = :module_name
    SITE_OWN_METHODS = :own_methods
    SITE_CANDIDATE = :candidate
    SITE_SOURCE_PARSE = :source_parse
    SITE_STATE_ANALYSIS = :state_analysis

    SITES = [SITE_MODULE_NAME, SITE_OWN_METHODS, SITE_CANDIDATE,
             SITE_SOURCE_PARSE, SITE_STATE_ANALYSIS].freeze

    LOSSY_SITES = [SITE_MODULE_NAME, SITE_OWN_METHODS, SITE_CANDIDATE].freeze

    SUBJECT_UNNAMED = "(module that cannot report a name)"

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
        @touches_state == true
      end

      def state_known?
        STATE_VERDICTS.include?(@touches_state)
      end

      def unanalysable?
        @touches_state == STATE_UNANALYSABLE
      end

      def unreadable_source?
        @touches_state == STATE_UNREADABLE
      end

      def reachable?
        return true if gated?
        return false unless zero_arity?

        touches_state? || unreadable_source?
      end

      def to_s
        "#{class_name}#{singleton? ? '.' : '#'}#{method_name}"
      end
    end

    class Suppression
      attr_reader :site, :subject, :error_class

      def initialize(site:, subject:, error_class:)
        @site = site
        @subject = subject
        @error_class = error_class
      end

      def lossy?
        LOSSY_SITES.include?(site)
      end

      def to_s
        "#{site} #{subject} (#{error_class})"
      end
    end

    class Report
      attr_reader :candidates, :scanned_modules, :suppressions

      def initialize(candidates, scanned_modules, suppressions)
        @candidates = candidates
        @scanned_modules = scanned_modules
        @suppressions = suppressions
      end

      def suppressed_count
        suppressions.length
      end

      def suppressions_by_site
        suppressions.each_with_object({}) do |suppression, counts|
          counts[suppression.site] = counts.fetch(suppression.site, 0) + 1
        end
      end

      def complete?
        suppressions.empty?
      end

      def candidates_lost?
        suppressions.any?(&:lossy?)
      end

      def unanalysable
        candidates.select(&:unanalysable?)
      end

      def fully_analysed?
        candidates.all?(&:state_known?)
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

      def prism_available?
        PRISM_AVAILABLE
      end
    end

    def initialize(namespace: nil)
      @namespace = namespace
      @candidates = []
      @definition_cache = {}
      @scanned_modules = 0
      @suppressions = []
    end

    def scan
      each_named_module do |mod, name|
        @scanned_modules += 1
        collect_instance_methods(mod, name)
        collect_singleton_methods(mod, name)
      end

      Report.new(@candidates.sort_by(&:to_s), @scanned_modules, @suppressions.freeze)
    end

    private

    attr_reader :namespace

    def suppress(site, subject, error)
      @suppressions << Suppression.new(site: site, subject: subject, error_class: error.class.name)
    end

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
    rescue StandardError => e
      suppress(SITE_MODULE_NAME, SUBJECT_UNNAMED, e)
      nil
    end

    def in_namespace?(name)
      namespace.nil? || name == namespace || name.start_with?("#{namespace}::")
    end

    def collect_instance_methods(mod, name)
      own = own_instance_methods(mod, name)

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

    def own_instance_methods(mod, name)
      (mod.instance_methods(false) + mod.private_instance_methods(false)).map(&:to_s)
    rescue StandardError => e
      suppress(SITE_OWN_METHODS, name, e)
      []
    end

    def qualified(name, method_name, singleton)
      "#{name}#{singleton ? '.' : '#'}#{method_name}"
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
        touches_state: state_reference_in(handle, qualified(name, method_name, singleton))
      )
    rescue StandardError, ScriptError => e
      suppress(SITE_CANDIDATE, qualified(name, method_name, singleton), e)
      nil
    end

    def format_location(location)
      return UNKNOWN_LOCATION unless location

      location.join(LOCATION_SEPARATOR)
    end

    def state_reference_in(handle, subject)
      return STATE_UNANALYSABLE unless PRISM_AVAILABLE

      path, line = handle.source_location
      return STATE_UNANALYSABLE unless path && line

      definitions = definitions_for(path)
      return STATE_UNREADABLE unless definitions

      node = definitions[line]
      return STATE_UNREADABLE unless node

      node.compact_child_nodes.any? { |child| state_reference?(child) }
    rescue StandardError, ScriptError => e
      suppress(SITE_STATE_ANALYSIS, subject, e)
      STATE_UNREADABLE
    end

    def definitions_for(path)
      return @definition_cache[path] if @definition_cache.key?(path)

      @definition_cache[path] = parse_definitions(path)
    end

    def parse_definitions(path)
      found = {}
      collect_definitions(Prism.parse_file(path).value, found)
      found
    rescue StandardError, ScriptError => e
      suppress(SITE_SOURCE_PARSE, path, e)
      nil
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
