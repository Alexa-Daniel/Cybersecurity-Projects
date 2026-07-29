# ©AngelaMos | 2026
# boundary_detector.rb

module Rube
  module Marshal
    class ReporterRequiredError < StandardError; end

    class BoundaryDetector
      POLICY_STRICT_ALLOWLIST = :strict_allowlist
      POLICY_DENY_SINKS_ONLY = :deny_sinks_only
      POLICY_OBSERVE_AND_LOG = :observe_and_log

      POLICIES = [POLICY_STRICT_ALLOWLIST, POLICY_DENY_SINKS_ONLY, POLICY_OBSERVE_AND_LOG].freeze

      PRIMITIVE_CLASS_NAMES = %w[].freeze

      REASON_INPUT_TYPE = "input is not a String"
      REASON_MALFORMED = "stream is not canonical Marshal: %s"
      REASON_SINK = "stream reaches %s#%s during load, before any allowlist can run"
      REASON_UNAPPROVED = "stream references unapproved class %s"
      REASON_KEY_DISPATCH = "stream puts %s in a hash key, so its #hash and #eql? run during " \
                            "load, before any allowlist can act"
      REASON_NONCANONICAL_VERSION = "stream declares Marshal %d.%d; every Ruby that can produce " \
                                    "this format emits %d.%d"

      LIMITATION_NOTICE = <<~NOTICE.freeze
        SECURITY LIMITATION

        Rube::Marshal::BoundaryDetector examines a bounded snapshot of Marshal bytes and
        applies a caller-selected policy before deserialization. An ACCEPT decision means
        only that this snapshot matched that policy.

        Acceptance does not make the payload safe, trusted, authenticated, or free of
        gadget behavior. This detector does not sandbox Ruby, audit the current
        implementations of allowlisted classes, freeze the runtime class graph, or prevent
        callbacks and implicit method dispatch that its parser or policy fails to model.
        Class allowlisting compares serialized names. It does not prove that the
        corresponding Ruby code is harmless.

        A payload carrying no sink tag can still reach dangerous code. The published
        CVE-2026-41316 chain produces zero sink tags because ERB defines no marshal_load.
        It is caught by class allowlisting alone, and an application that allowlists ERB
        will accept it.
      NOTICE

      class Decision
        attr_reader :reason, :snapshot, :result

        def initialize(accepted:, reason: nil, snapshot: nil, result: nil, observed: false, would_reject: false)
          @accepted = accepted
          @reason = reason
          @snapshot = snapshot
          @result = result
          @observed = observed
          @would_reject = would_reject
        end

        def accepted?
          @accepted
        end

        def rejected?
          !@accepted
        end

        def observed?
          @observed
        end

        def would_reject?
          @would_reject
        end
      end

      def initialize(policy: POLICY_STRICT_ALLOWLIST, allowed_class_names: [], limits: Limits.new, reporter: nil)
        raise ArgumentError, "unknown policy #{policy}" unless POLICIES.include?(policy)
        raise ReporterRequiredError, "#{POLICY_OBSERVE_AND_LOG} requires a reporter" if
          policy == POLICY_OBSERVE_AND_LOG && reporter.nil?

        @policy = policy
        @allowed_class_names = allowed_class_names.map(&:to_s).freeze
        @limits = limits
        @reporter = reporter
      end

      def inspect_stream(input)
        return reject(REASON_INPUT_TYPE) unless input.is_a?(String)

        snapshot = input.dup.force_encoding(Encoding::BINARY).freeze
        result = Parser.new(snapshot, limits: limits).parse
        evaluate(result, snapshot)
      rescue StreamError => e
        reject(format(REASON_MALFORMED, e.class.name.split("::").last))
      end

      private

      attr_reader :policy, :allowed_class_names, :limits, :reporter

      def evaluate(result, snapshot)
        violation = violation_for(result)
        return accept(snapshot, result) unless violation

        return observe(violation, snapshot, result) if policy == POLICY_OBSERVE_AND_LOG

        reject(violation)
      end

      def violation_for(result)
        sink = result.sinks.first
        return format(REASON_SINK, sink.class_name, sink.sink_method) if sink

        key = result.dispatching_hash_keys.first
        return format(REASON_KEY_DISPATCH, key.effective_class_name) if key

        return nil if policy == POLICY_DENY_SINKS_ONLY

        unless result.canonical_version?
          return format(REASON_NONCANONICAL_VERSION, result.major, result.minor,
                        Constants::MAJOR_VERSION, Constants::MINOR_VERSION)
        end

        unapproved = result.class_names.reject { |name| allowed_class_names.include?(name) }
        return format(REASON_UNAPPROVED, unapproved.join(", ")) unless unapproved.empty?

        nil
      end

      def observe(violation, snapshot, result)
        reporter.call(violation)
        Decision.new(accepted: true, reason: violation, snapshot: snapshot,
                     result: result, observed: true, would_reject: true)
      end

      def accept(snapshot, result)
        Decision.new(accepted: true, snapshot: snapshot, result: result)
      end

      def reject(reason)
        Decision.new(accepted: false, reason: reason)
      end
    end
  end
end
