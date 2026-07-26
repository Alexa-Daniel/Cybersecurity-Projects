# ©AngelaMos | 2026
# scanner_test.rb

require_relative "test_helper"

module Rube
  class ScannerTest < Minitest::Test
    def scan(**options)
      Scanner.new(**options).scan
    end

    def local_scan
      scan(namespace: "Rube::ScannerTest")
    end

    def candidates_for(class_name)
      local_scan.candidates.select { |c| c.class_name == class_name }
    end

    def test_finds_gated_sink_defined_on_a_class
      found = candidates_for("Rube::ScannerTest::GatedFixture")
      assert_equal ["marshal_load"], found.map(&:method_name)
      assert_equal :gated, found.first.gate
    end

    def test_finds_singleton_load_as_gated_sink
      found = candidates_for("Rube::ScannerTest::UserDefFixture")
      assert_includes found.map(&:method_name), "_load"
    end

    def test_finds_ungated_dispatch_method
      found = candidates_for("Rube::ScannerTest::UngatedFixture")
      assert_equal ["hash"], found.map(&:method_name)
      assert_equal :ungated, found.first.gate
    end

    def test_finds_method_missing_as_ungated
      found = candidates_for("Rube::ScannerTest::ProxyFixture")
      assert_includes found.map(&:method_name), "method_missing"
    end

    def test_negative_control_class_with_no_auto_invoked_methods_is_not_reported
      assert_empty candidates_for("Rube::ScannerTest::InertFixture")
    end

    def test_precision_control_inherited_methods_are_not_reported
      assert_empty candidates_for("Rube::ScannerTest::InheritsOnlyFixture")
    end

    def test_candidates_carry_source_location
      candidate = candidates_for("Rube::ScannerTest::GatedFixture").first
      refute_nil candidate.source_location
      assert_includes candidate.source_location, "scanner_test.rb"
    end

    def test_candidates_report_arity
      candidate = candidates_for("Rube::ScannerTest::GatedFixture").first
      assert_equal 1, candidate.arity
    end

    def test_ungated_methods_report_zero_arity
      candidate = candidates_for("Rube::ScannerTest::UngatedFixture").first
      assert_predicate candidate, :zero_arity?
    end

    def test_reachability_via_instance_variable_read
      candidate = candidates_for("Rube::ScannerTest::StatefulFixture").first
      assert_predicate candidate, :touches_state?
      assert_predicate candidate, :reachable?
    end

    def test_reachability_via_implicit_self_call
      candidate = candidates_for("Rube::ScannerTest::AccessorFixture").first
      assert_predicate candidate, :touches_state?, "attr_reader access must count as touching state"
      assert_predicate candidate, :reachable?
    end

    def test_negative_control_stateless_method_is_not_reachable
      candidate = candidates_for("Rube::ScannerTest::StatelessFixture").first
      refute_predicate candidate, :touches_state?
      refute_predicate candidate, :reachable?
    end

    def test_gated_sinks_are_reachable_regardless_of_state
      candidate = candidates_for("Rube::ScannerTest::GatedFixture").first
      assert_predicate candidate, :reachable?
    end

    def test_reachable_is_a_strict_subset_of_candidates
      report = scan(namespace: "Gem")
      refute_empty report.reachable
      assert_operator report.reachable.length, :<, report.candidates.length,
                      "reachability filter kept everything, so it is not filtering"
    end

    def test_rediscovers_accessor_backed_stdlib_sink
      report = scan(namespace: "Gem")
      names = report.reachable.map(&:to_s)
      assert_includes names, "Gem::Requirement#hash"
    end

    def test_rediscovers_a_real_stdlib_sink_without_hardcoding
      report = scan(namespace: "Gem")
      names = report.gated.map { |c| "#{c.class_name}##{c.method_name}" }
      assert_includes names, "Gem::Requirement#marshal_load"
      refute_includes Scanner::GATED_METHODS + Scanner::UNGATED_METHODS, "Gem::Requirement"
    end

    def test_namespace_filter_excludes_everything_else
      report = scan(namespace: "Rube::ScannerTest")
      assert(report.candidates.all? { |c| c.class_name.start_with?("Rube::ScannerTest") })
    end

    def test_report_partitions_gated_and_ungated
      report = local_scan
      assert_equal report.candidates.length, report.gated.length + report.ungated.length
      assert_empty(report.gated & report.ungated)
    end

    def test_scan_is_deterministic
      first = local_scan.candidates.map(&:to_s).sort
      second = local_scan.candidates.map(&:to_s).sort
      assert_equal first, second
    end

    def test_anonymous_classes_are_skipped
      Class.new { def marshal_load(data); end }
      refute(local_scan.candidates.any? { |c| c.class_name.nil? || c.class_name.empty? })
    end

    def test_scanning_does_not_instantiate_anything
      refute GatedFixture.instantiated
      local_scan
      refute GatedFixture.instantiated, "scanner constructed a candidate class"
    end

    class GatedFixture
      @instantiated = false

      class << self
        attr_accessor :instantiated
      end

      def marshal_load(data); end
    end

    class UserDefFixture
      def self._load(data)
        allocate
      end
    end

    class UngatedFixture
      def hash
        super
      end
    end

    class ProxyFixture
      def method_missing(name, *args)
        super
      end

      def respond_to_missing?(name, include_private = false)
        super
      end
    end

    class StatefulFixture
      def hash
        @seed.to_i
      end
    end

    class AccessorFixture
      attr_reader :seed

      def hash
        seed.to_i
      end
    end

    class StatelessFixture
      def hash
        42
      end
    end

    class InertFixture
      def ordinary_method; end

      def another_one(argument); end
    end

    class InheritsOnlyFixture
    end
  end
end
