# ©AngelaMos | 2026
# chains_test.rb
# frozen_string_literal: true

require_relative "test_helper"

module Rube
  module Chains
    class ChainsTest < Minitest::Test
      CANARY_PATH = "/tmp/rube-canary"
      CANARY_MARKER = "fired"

      def chain
        ErbDefMethod.canary(CANARY_PATH, CANARY_MARKER)
      end

      def test_registry_excludes_the_base_class
        refute_includes Chains.all, Base
      end

      def test_registry_contains_the_erb_chain
        assert_includes Chains.all, ErbDefMethod
      end

      def test_find_by_name
        assert_equal ErbDefMethod, Chains.find("erb-def-method")
      end

      def test_find_raises_on_unknown_name
        assert_raises(UnknownChainError) { Chains.find("no-such-chain") }
      end

      def test_metadata_is_complete
        assert_equal "erb-def-method", ErbDefMethod.chain_name
        assert_equal "def_method", ErbDefMethod.vector
        assert_equal "CVE-2026-41316", ErbDefMethod.cve
        assert_equal "erb", ErbDefMethod.target_gem
      end

      def test_affects_reproduces_the_published_ranges
        { "2.2.3" => true, "4.0.2" => true, "4.0.3" => true, "4.0.4" => true,
          "5.0.0" => true, "6.0.1" => true, "6.0.2" => true, "6.0.3" => true,
          "4.0.3.1" => false, "4.0.4.1" => false, "6.0.1.1" => false, "6.0.4" => false }.each do |version, expected|
          assert_equal expected, ErbDefMethod.affects?(version), "erb #{version}"
        end
      end

      def test_for_version_selects_matching_chains
        assert_includes Chains.for_version("erb", "6.0.1"), ErbDefMethod
        assert_empty Chains.for_version("erb", "6.0.1.1")
      end

      def test_generate_returns_an_object_not_bytes
        assert_kind_of ERB, chain.generate
      end

      def test_generated_object_carries_the_payload_source
        assert_includes chain.generate.instance_variable_get(:@src), CANARY_PATH
      end

      def test_generated_object_omits_the_init_sentinel
        refute_includes chain.generate.instance_variables, :@_init
      end

      def test_src_closes_the_injected_def_before_the_payload
        assert_match(/\A#\nend\n/, chain.src)
      end

      def test_serialize_produces_a_parseable_marshal_stream
        blob = chain.serialize
        assert_equal [Rube::Marshal::Constants::MAJOR_VERSION, Rube::Marshal::Constants::MINOR_VERSION],
                     [blob.getbyte(0), blob.getbyte(1)]
        assert_equal :object, Rube::Marshal::Parser.new(blob).parse.root.type
      end

      def test_payload_is_visible_to_the_parser_without_deserializing
        result = Rube::Marshal::Parser.new(chain.serialize).parse
        assert_includes result.class_names, "ERB"
      end

      def test_base_refuses_to_generate
        assert_raises(NotImplementedByChainError) { Base.new.generate }
      end

      def test_base_refuses_metadata
        assert_raises(NotImplementedByChainError) { Base.metadata }
      end
    end
  end
end
