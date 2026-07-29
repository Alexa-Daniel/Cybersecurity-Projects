# ©AngelaMos | 2026
# node.rb

module Rube
  module Marshal
    class Node
      STRING_BACKED_TYPES = %i[string regexp].freeze
      WRAPPER_TYPES = %i[user_class extended].freeze

      attr_reader :type, :tag, :children, :instance_variables_map, :auxiliary
      attr_accessor :value, :class_name, :link_target

      def initialize(type:, tag: nil, value: nil, class_name: nil)
        @type = type
        @tag = tag
        @value = value
        @class_name = class_name
        @children = []
        @instance_variables_map = {}
        @auxiliary = []
      end

      def sink?
        Constants::SINK_TAGS.include?(tag)
      end

      def sink_method
        Constants::SINK_METHODS[tag]
      end

      def gated?
        Constants::GATED_SINK_TAGS.include?(tag)
      end

      def dispatches_key_methods?
        return link_target ? link_target.dispatches_key_methods? : false if type == :object_link
        return false unless class_name
        return !string_backed? if WRAPPER_TYPES.include?(type)

        true
      end

      def effective_class_name
        link_target ? link_target.class_name : class_name
      end

      def string_backed?
        wrapped = children.first
        return false unless wrapped

        STRING_BACKED_TYPES.include?(wrapped.type)
      end

      def each(&block)
        return enum_for(:each) unless block

        yield self
        children.each { |child| child.each(&block) }
        auxiliary.each { |child| child.each(&block) }
      end
    end

    class Result
      attr_reader :root, :major, :minor

      def initialize(root, major:, minor:)
        @root = root
        @major = major
        @minor = minor
      end

      def canonical_version?
        major == Constants::MAJOR_VERSION && minor == Constants::MINOR_VERSION
      end

      def nodes
        root.each
      end

      def class_names
        nodes.filter_map(&:class_name).uniq
      end

      def sinks
        nodes.select(&:sink?)
      end

      def gated_sinks
        sinks.select(&:gated?)
      end

      def hash_keys
        nodes.select { |node| node.type == :hash }
             .flat_map(&:children)
             .select { |child| child.type == :pair }
             .filter_map { |pair| pair.children.first }
      end

      def dispatching_hash_keys
        hash_keys.select(&:dispatches_key_methods?)
      end
    end
  end
end
