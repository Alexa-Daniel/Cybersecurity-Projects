# ©AngelaMos | 2026
# node.rb

module Rube
  module Marshal
    class Node
      attr_reader :type, :tag, :children, :instance_variables_map
      attr_accessor :value, :class_name

      def initialize(type:, tag: nil, value: nil, class_name: nil)
        @type = type
        @tag = tag
        @value = value
        @class_name = class_name
        @children = []
        @instance_variables_map = {}
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

      def each(&block)
        return enum_for(:each) unless block

        yield self
        children.each { |child| child.each(&block) }
        instance_variables_map.each_value { |child| child.each(&block) }
      end
    end

    class Result
      attr_reader :root

      def initialize(root)
        @root = root
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
    end
  end
end
