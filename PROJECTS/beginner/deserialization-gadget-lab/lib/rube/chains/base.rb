# ©AngelaMos | 2026
# base.rb

module Rube
  module Chains
    class ChainError < StandardError; end

    class NotImplementedByChainError < ChainError; end

    class Base
      NAMESPACE_SEPARATOR = "::"
      SUBCLASS_MUST_DEFINE = "chain must define"

      class << self
        def inherited(subclass)
          super
          Chains.register(subclass)
        end

        def metadata
          raise NotImplementedByChainError, "#{SUBCLASS_MUST_DEFINE} metadata"
        end

        def chain_name
          metadata.fetch(:name)
        end

        def vector
          metadata.fetch(:vector)
        end

        def cve
          metadata.fetch(:cve)
        end

        def target_gem
          metadata.fetch(:gem)
        end

        def affected_requirements
          metadata.fetch(:affected).map { |constraint| Gem::Requirement.new(constraint) }
        end

        def affects?(version)
          candidate = Gem::Version.new(version.to_s)
          affected_requirements.any? { |requirement| requirement.satisfied_by?(candidate) }
        end
      end

      def generate
        raise NotImplementedByChainError, "#{SUBCLASS_MUST_DEFINE} generate"
      end

      def serialize
        ::Marshal.dump(generate)
      end
    end
  end
end
