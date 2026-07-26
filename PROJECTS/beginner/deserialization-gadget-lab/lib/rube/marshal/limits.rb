# ©AngelaMos | 2026
# limits.rb

module Rube
  module Marshal
    class Limits
      DEFAULT_MAX_BYTES = 1_048_576
      DEFAULT_MAX_DEPTH = 64
      DEFAULT_MAX_NODES = 10_000
      DEFAULT_MAX_REGISTERED_OBJECTS = 4_096
      DEFAULT_MAX_SYMBOL_DEFINITIONS = 256
      DEFAULT_MAX_COLLECTION_ENTRIES = 1_024
      DEFAULT_MAX_SCALAR_BYTES = 262_144
      DEFAULT_MAX_TOTAL_SCALAR_BYTES = 524_288
      DEFAULT_MAX_OBJECT_LINKS = 2_048

      ROLE_BYTES = "stream bytes"
      ROLE_NODES = "nodes"
      ROLE_REGISTERED = "registered objects"
      ROLE_SYMBOLS = "symbol definitions"
      ROLE_ENTRIES = "collection entries"
      ROLE_SCALAR = "scalar bytes"
      ROLE_TOTAL_SCALAR = "total scalar bytes"
      ROLE_LINKS = "object links"

      attr_reader :max_bytes, :max_depth, :max_nodes, :max_registered_objects,
                  :max_symbol_definitions, :max_collection_entries,
                  :max_scalar_bytes, :max_total_scalar_bytes, :max_object_links

      def initialize(
        max_bytes: DEFAULT_MAX_BYTES,
        max_depth: DEFAULT_MAX_DEPTH,
        max_nodes: DEFAULT_MAX_NODES,
        max_registered_objects: DEFAULT_MAX_REGISTERED_OBJECTS,
        max_symbol_definitions: DEFAULT_MAX_SYMBOL_DEFINITIONS,
        max_collection_entries: DEFAULT_MAX_COLLECTION_ENTRIES,
        max_scalar_bytes: DEFAULT_MAX_SCALAR_BYTES,
        max_total_scalar_bytes: DEFAULT_MAX_TOTAL_SCALAR_BYTES,
        max_object_links: DEFAULT_MAX_OBJECT_LINKS
      )
        @max_bytes = max_bytes
        @max_depth = max_depth
        @max_nodes = max_nodes
        @max_registered_objects = max_registered_objects
        @max_symbol_definitions = max_symbol_definitions
        @max_collection_entries = max_collection_entries
        @max_scalar_bytes = max_scalar_bytes
        @max_total_scalar_bytes = max_total_scalar_bytes
        @max_object_links = max_object_links
      end

      def permissive
        self.class.new(
          max_bytes: Float::INFINITY,
          max_depth: Constants::DEFAULT_MAX_DEPTH,
          max_nodes: Float::INFINITY,
          max_registered_objects: Float::INFINITY,
          max_symbol_definitions: Float::INFINITY,
          max_collection_entries: Float::INFINITY,
          max_scalar_bytes: Float::INFINITY,
          max_total_scalar_bytes: Float::INFINITY,
          max_object_links: Float::INFINITY
        )
      end
    end

    class Budget
      def initialize(limits)
        @limits = limits
        @nodes = 0
        @registered = 0
        @symbols = 0
        @links = 0
        @scalar_total = 0
      end

      def node!
        @nodes += 1
        check(@nodes, limits.max_nodes, Limits::ROLE_NODES)
      end

      def registered!
        @registered += 1
        check(@registered, limits.max_registered_objects, Limits::ROLE_REGISTERED)
      end

      def symbol!
        @symbols += 1
        check(@symbols, limits.max_symbol_definitions, Limits::ROLE_SYMBOLS)
      end

      def link!
        @links += 1
        check(@links, limits.max_object_links, Limits::ROLE_LINKS)
      end

      def entries!(count)
        check(count, limits.max_collection_entries, Limits::ROLE_ENTRIES)
      end

      def scalar!(size)
        check(size, limits.max_scalar_bytes, Limits::ROLE_SCALAR)
        @scalar_total += size
        check(@scalar_total, limits.max_total_scalar_bytes, Limits::ROLE_TOTAL_SCALAR)
      end

      private

      attr_reader :limits

      def check(value, ceiling, role)
        return if value <= ceiling

        raise LimitExceededError, "#{role} #{value} exceeds #{ceiling}"
      end
    end
  end
end
