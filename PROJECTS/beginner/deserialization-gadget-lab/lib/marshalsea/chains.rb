# ©AngelaMos | 2026
# chains.rb
# frozen_string_literal: true

module Marshalsea
  module Chains
    class UnknownChainError < StandardError; end

    @registry = []

    class << self
      def registry
        @registry.dup.freeze
      end

      def register(chain)
        @registry << chain unless @registry.include?(chain)
      end

      def all
        @registry.reject { |chain| chain == Base }
      end

      def find(name)
        all.find { |chain| chain.chain_name == name } ||
          raise(UnknownChainError, name.to_s)
      end

      def for_version(gem_name, version)
        all.select { |chain| chain.target_gem == gem_name && chain.affects?(version) }
      end
    end
  end
end

require_relative "chains/base"
require_relative "chains/erb_def_method"
