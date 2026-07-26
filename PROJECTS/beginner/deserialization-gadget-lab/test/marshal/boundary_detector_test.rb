# ©AngelaMos | 2026
# boundary_detector_test.rb

require_relative "../test_helper"

module Rube
  module Marshal
    class BoundaryDetectorTest < Minitest::Test
      BENIGN = { "user" => "guest", "roles" => [1, 2, 3], "flag" => true }.freeze
      CANARY_PATH = "/tmp/rube-canary"
      CANARY_MARKER = "fired"

      def detector(**options)
        BoundaryDetector.new(**options)
      end

      def benign_blob
        ::Marshal.dump(BENIGN)
      end

      def sink_blob
        ::Marshal.dump(Gem::Requirement.new(">= 0"))
      end

      def cve_blob
        Rube::Chains::ErbDefMethod.canary(CANARY_PATH, CANARY_MARKER).serialize
      end

      def test_default_policy_is_strict_allowlist
        assert_equal BoundaryDetector::POLICY_STRICT_ALLOWLIST,
                     detector.send(:policy)
      end

      def test_accepts_primitive_only_stream_with_an_empty_allowlist
        assert_predicate detector.inspect_stream(benign_blob), :accepted?
      end

      def test_rejects_non_string_input_without_converting_it
        hostile = Object.new
        def hostile.to_s
          raise "to_s must never be called on untrusted input"
        end

        decision = detector.inspect_stream(hostile)
        assert_predicate decision, :rejected?
        assert_equal BoundaryDetector::REASON_INPUT_TYPE, decision.reason
      end

      def test_rejects_a_sink_bearing_stream
        decision = detector.inspect_stream(sink_blob)
        assert_predicate decision, :rejected?
        assert_includes decision.reason, "Gem::Requirement#marshal_load"
      end

      def test_allowlisting_a_class_does_not_exempt_its_sink
        decision = detector(allowed_class_names: %w[Gem::Requirement Gem::Version])
                   .inspect_stream(sink_blob)
        assert_predicate decision, :rejected?
        assert_includes decision.reason, "marshal_load"
      end

      def test_rejects_unapproved_class_names
        decision = detector.inspect_stream(cve_blob)
        assert_predicate decision, :rejected?
        assert_includes decision.reason, "ERB"
      end

      def test_accepts_an_approved_class
        decision = detector(allowed_class_names: %w[ERB]).inspect_stream(cve_blob)
        assert_predicate decision, :accepted?
      end

      def test_documented_bypass_is_real_deny_sinks_only_accepts_the_cve_payload
        decision = detector(policy: BoundaryDetector::POLICY_DENY_SINKS_ONLY)
                   .inspect_stream(cve_blob)
        assert_predicate decision, :accepted?,
                         "the limitation notice claims this bypass exists, so it must be demonstrable"
      end

      def test_deny_sinks_only_still_rejects_sinks
        decision = detector(policy: BoundaryDetector::POLICY_DENY_SINKS_ONLY)
                   .inspect_stream(sink_blob)
        assert_predicate decision, :rejected?
      end

      def test_observe_and_log_requires_a_reporter
        assert_raises(ReporterRequiredError) do
          detector(policy: BoundaryDetector::POLICY_OBSERVE_AND_LOG)
        end
      end

      def test_observe_and_log_accepts_but_records_the_violation
        seen = []
        decision = detector(policy: BoundaryDetector::POLICY_OBSERVE_AND_LOG,
                            reporter: ->(reason) { seen << reason })
                   .inspect_stream(cve_blob)

        assert_predicate decision, :accepted?
        assert_predicate decision, :observed?
        assert_predicate decision, :would_reject?
        assert_equal 1, seen.length
      end

      def test_observe_and_log_still_rejects_malformed_input
        decision = detector(policy: BoundaryDetector::POLICY_OBSERVE_AND_LOG,
                            reporter: ->(_) {})
                   .inspect_stream("\x04\x08[\xFA")
        assert_predicate decision, :rejected?
      end

      def test_rejects_unknown_policy
        assert_raises(ArgumentError) { detector(policy: :yolo) }
      end

      def test_rejects_malformed_stream_with_a_named_reason
        decision = detector.inspect_stream("\x04\x08[\xFA")
        assert_predicate decision, :rejected?
        assert_includes decision.reason, "MalformedCountError"
      end

      def test_returns_a_frozen_snapshot_on_accept
        decision = detector.inspect_stream(benign_blob)
        assert_predicate decision.snapshot, :frozen?
      end

      def test_snapshot_is_independent_of_a_mutated_original
        original = +benign_blob
        decision = detector.inspect_stream(original)
        original << "tampered"
        refute_includes decision.snapshot, "tampered"
      end

      def test_enforces_a_byte_ceiling_before_parsing
        limits = Limits.new(max_bytes: 8)
        decision = detector(limits: limits).inspect_stream(benign_blob)
        assert_predicate decision, :rejected?
        assert_includes decision.reason, "LimitExceededError"
      end

      def test_enforces_a_depth_ceiling
        deep = "\x04\x08" + ("[\x06" * 80) + "0"
        decision = detector.inspect_stream(deep)
        assert_predicate decision, :rejected?
      end

      def test_enforces_a_collection_entry_ceiling
        limits = Limits.new(max_collection_entries: 2)
        decision = detector(limits: limits).inspect_stream(::Marshal.dump([1, 2, 3, 4, 5]))
        assert_predicate decision, :rejected?
      end

      def test_enforces_a_symbol_ceiling
        limits = Limits.new(max_symbol_definitions: 2)
        blob = ::Marshal.dump(%i[a b c d e f])
        decision = detector(limits: limits).inspect_stream(blob)
        assert_predicate decision, :rejected?
      end

      def test_enforces_a_node_ceiling
        limits = Limits.new(max_nodes: 5)
        decision = detector(limits: limits).inspect_stream(::Marshal.dump((1..50).to_a))
        assert_predicate decision, :rejected?
      end

      def test_never_exposes_a_safety_claiming_api
        %i[safe? trusted? sanitized? safe_load].each do |forbidden|
          refute_respond_to detector, forbidden,
                            "#{forbidden} implies a guarantee this detector cannot make"
        end
      end

      def test_ships_a_limitation_notice_that_names_the_bypass
        notice = BoundaryDetector::LIMITATION_NOTICE
        assert_includes notice, "does not make the payload safe"
        assert_includes notice, "CVE-2026-41316"
        assert_includes notice, "zero sink tags"
      end

      def test_detector_never_calls_marshal_load
        fired = false
        tracer = TracePoint.new(:call, :c_call) do |tp|
          fired = true if tp.method_id == :load && tp.self.equal?(::Marshal)
        end
        tracer.enable { detector.inspect_stream(cve_blob) }
        refute fired
      end
    end
  end
end
