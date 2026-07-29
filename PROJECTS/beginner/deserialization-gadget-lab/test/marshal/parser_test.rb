# ©AngelaMos | 2026
# parser_test.rb

require_relative "../test_helper"
require_relative "../support/adversarial_corpus"

module Rube
  module Marshal
    class ParserTest < Minitest::Test
      def parse(blob)
        Parser.new(blob).parse
      end

      def roundtrip(object)
        parse(::Marshal.dump(object)).root
      end

      def test_rejects_empty_stream
        assert_raises(TruncatedStreamError) { parse("") }
      end

      def test_rejects_header_only
        assert_raises(TruncatedStreamError) { parse("\x04\x08") }
      end

      def test_rejects_wrong_major_version
        assert_raises(UnsupportedVersionError) { parse("\x05\x08\x30") }
      end

      def test_rejects_future_minor_version
        assert_raises(UnsupportedVersionError) { parse("\x04\x09\x30") }
      end

      def test_accepts_older_minor_version
        assert_equal :nil, parse("\x04\x07\x30").root.type
      end

      def test_rejects_unknown_tag
        assert_raises(UnknownTagError) { parse("\x04\x08\x00") }
      end

      def test_rejects_trailing_bytes
        assert_raises(TrailingBytesError) { parse(::Marshal.dump(nil) + "junk") }
      end

      def test_parses_nil
        assert_equal :nil, roundtrip(nil).type
      end

      def test_parses_booleans
        assert_equal true, roundtrip(true).value
        assert_equal false, roundtrip(false).value
      end

      def test_parses_fixnum_across_every_encoding_width
        [0, 1, 5, 122, 123, 255, 256, 65_535, 65_536, 1_073_741_823,
         -1, -123, -124, -256, -65_536, -1_073_741_824].each do |n|
          assert_equal n, roundtrip(n).value, "fixnum #{n} did not round-trip"
        end
      end

      def test_parses_bignum_both_signs
        [2**64, -(2**64), 2**128 + 7].each do |n|
          assert_equal n, roundtrip(n).value, "bignum #{n} did not round-trip"
        end
      end

      def test_parses_float
        assert_in_delta 3.5, roundtrip(3.5).value, 0.0
      end

      def test_parses_symbol
        assert_equal :marshal_load, roundtrip(:marshal_load).value
      end

      def test_parses_string_through_ivar_wrapper
        node = roundtrip("hello")
        assert_equal :string, node.type
        assert_equal "hello", node.value
      end

      def test_parses_array
        node = roundtrip([1, 2, 3])
        assert_equal :array, node.type
        assert_equal [1, 2, 3], node.children.map(&:value)
      end

      def test_parses_nested_array
        node = roundtrip([1, [2, [3]]])
        assert_equal 3, node.children.last.children.last.children.first.value
      end

      def test_parses_hash
        node = roundtrip({ a: 1 })
        assert_equal :hash, node.type
        assert_equal 1, node.children.length
      end

      def test_object_links_are_zero_indexed
        cyclic = []
        cyclic << cyclic
        node = roundtrip(cyclic)
        link = node.children.first
        assert_equal :object_link, link.type
        assert_equal 0, link.value
      end

      def test_rejects_out_of_bounds_object_link
        assert_raises(InvalidLinkError) { parse("\x04\x08@\x0a") }
      end

      def test_rejects_out_of_bounds_symlink
        assert_raises(InvalidLinkError) { parse("\x04\x08;\x0a") }
      end

      def test_resolves_symlink_to_prior_symbol
        node = roundtrip([:same, :same])
        assert_equal :symlink, node.children.last.type
        assert_equal :same, node.children.last.value
      end

      def test_extracts_class_name_from_plain_object
        blob = ::Marshal.dump(Fixture.new)
        result = parse(blob)
        assert_includes result.class_names, "Rube::Marshal::ParserTest::Fixture"
      end

      def test_extracts_class_name_without_instantiating
        refute Fixture.instantiated, "parser must not construct the class"
        parse(::Marshal.dump(Fixture.new))
        refute Fixture.instantiated, "parser instantiated a class during parse"
      end

      def test_flags_usermarshal_as_sink
        result = parse(::Marshal.dump(UserMarshalFixture.new))
        sink = result.sinks.first
        refute_nil sink
        assert_equal "marshal_load", sink.sink_method
        assert_equal "Rube::Marshal::ParserTest::UserMarshalFixture", sink.class_name
      end

      def test_flags_userdef_as_sink
        result = parse(::Marshal.dump(UserDefFixture.new))
        assert_equal "_load", result.sinks.first.sink_method
      end

      def test_clean_payload_reports_no_sinks
        assert_empty parse(::Marshal.dump([1, "two", :three, { a: 1 }])).sinks
      end

      def test_rejects_truncated_string_body
        assert_raises(TruncatedStreamError) { parse("\x04\x08\"\x0aab") }
      end

      def test_rejects_truncated_array_elements
        assert_raises(TruncatedStreamError) { parse("\x04\x08[\x08i\x06") }
      end

      def test_rejects_truncated_multibyte_fixnum
        assert_raises(TruncatedStreamError) { parse("\x04\x08i\x03\x01") }
      end

      def test_rejects_negative_array_count
        assert_raises(MalformedCountError) { parse("\x04\x08[\xFA") }
      end

      def test_rejects_negative_hash_count
        assert_raises(MalformedCountError) { parse("\x04\x08{\xFA") }
      end

      def test_rejects_negative_bignum_word_count
        assert_raises(MalformedCountError) { parse("\x04\x08l+\xFA") }
      end

      def test_rejects_negative_instance_variable_count
        assert_raises(MalformedCountError) { parse("\x04\x08I\"\x06a\xFA") }
      end

      def test_rejects_negative_string_length
        assert_raises(MalformedCountError) { parse("\x04\x08\"\xFA") }
      end

      def test_rejects_negative_struct_member_count
        assert_raises(MalformedCountError) { parse("\x04\x08S:\x06A\xFA") }
      end

      def test_negative_counts_never_rewind_the_cursor
        parser = Parser.new("\x04\x08\"\xFA")
        assert_raises(MalformedCountError) { parser.parse }
      end

      def test_every_malformed_count_stays_inside_the_stream_error_hierarchy
        ["\x04\x08[\xFA", "\x04\x08{\xFA", "\x04\x08l+\xFA", "\x04\x08\"\xFA"].each do |blob|
          parse(blob)
          flunk "expected #{blob.inspect} to be rejected"
        rescue StreamError
          pass
        rescue StandardError => e
          flunk "#{blob.inspect} leaked #{e.class} outside StreamError"
        end
      end

      def test_rejects_negative_object_link_index
        assert_raises(InvalidLinkError) { parse("\x04\x08[\x06@\xFA") }
      end

      def test_rejects_negative_symlink_index
        assert_raises(InvalidLinkError) { parse("\x04\x08[\x07:\x06a;\xFA") }
      end

      def test_sink_in_an_instance_variable_name_position_is_still_reported
        result = parse("\x04\x08I\"\x06a\x06u:\x09Evil\x06x0")
        assert_includes result.class_names, "Evil"
        assert_equal ["Evil#_load"], result.sinks.map { |s| "#{s.class_name}##{s.sink_method}" }
      end

      def tripwires(blob)
        parse(blob).sinks.select { |node| node.class_name == AdversarialCorpus::TRIPWIRE_CLASS }
      end

      def test_class_name_node_is_traversable
        result = parse(::Marshal.dump(Fixture.new))
        names = result.nodes.select { |node| node.type == :symbol }.map(&:value)
        assert_includes names, :"Rube::Marshal::ParserTest::Fixture"
      end

      def test_class_name_slot_gadget_is_reachable_in_every_slot
        blind = AdversarialCorpus::CLASS_NAME_SLOTS.reject { |_slot, bytes| tripwires(bytes).any? }

        assert_empty blind.keys,
                     "class-name node discarded, hiding a sink, in: #{blind.keys.join(', ')}"
      end

      def test_class_name_slot_gadget_is_counted_once_per_slot
        duplicated = AdversarialCorpus::CLASS_NAME_SLOTS.select { |_slot, bytes| tripwires(bytes).length > 1 }

        assert_empty duplicated.keys, "a node must be traversed exactly once"
      end

      def test_distinct_instance_variable_names_reach_the_sink
        assert_equal 1, tripwires(AdversarialCorpus::IVAR_DISTINCT_NAMES_CONTROL).length,
                     "control failed, so the collision tests below would prove nothing"
      end

      def test_duplicate_instance_variable_names_do_not_delete_a_sink
        blind = AdversarialCorpus::IVAR_COLLISION_SHAPES.reject { |_shape, bytes| tripwires(bytes).any? }

        assert_empty blind.keys,
                     "duplicate ivar name deleted a subtree in: #{blind.keys.join(', ')}"
      end

      def test_duplicate_instance_variable_names_retain_both_values
        AdversarialCorpus::IVAR_COLLISION_SHAPES.each do |shape, bytes|
          nils = parse(bytes).nodes.count { |node| node.type == :nil }
          assert_equal 2, nils, "#{shape} lost an instance variable value node"
        end
      end

      def test_rejects_depth_beyond_limit
        deep = "\x04\x08" + ("[\x06" * (Constants::DEFAULT_MAX_DEPTH + 5)) + "0"
        assert_raises(DepthLimitError) { parse(deep) }
      end

      def test_honours_custom_depth_limit
        blob = ::Marshal.dump([[[1]]])
        assert_raises(DepthLimitError) { Parser.new(blob, max_depth: 2).parse }
      end

      def load_watcher
        fired = false
        tracer = TracePoint.new(:call, :c_call) do |tp|
          fired = true if tp.method_id == :load && tp.self.equal?(::Marshal)
        end
        tracer.enable { yield }
        fired
      end

      def test_load_watcher_oracle_is_live
        assert load_watcher { ::Marshal.load(::Marshal.dump([1, 2])) },
               "oracle failed to observe a real Marshal.load, so the next test would pass vacuously"
      end

      def test_never_calls_marshal_load
        blob = ::Marshal.dump(UserMarshalFixture.new)
        refute load_watcher { parse(blob) }, "parser invoked Marshal.load"
      end

      def test_never_calls_marshal_load_on_gadget_shaped_payload
        blob = ::Marshal.dump(Gem::Requirement.new(">= 0"))
        refute load_watcher { parse(blob) }, "parser invoked Marshal.load"
      end

      class Fixture
        @instantiated = false

        class << self
          attr_accessor :instantiated
        end

        def initialize
          @marker = "value"
        end
      end

      class UserMarshalFixture
        def marshal_dump
          ["payload"]
        end

        def marshal_load(data); end
      end

      class UserDefFixture
        def _dump(_depth)
          "opaque"
        end

        def self._load(_data)
          new
        end
      end
    end
  end
end
