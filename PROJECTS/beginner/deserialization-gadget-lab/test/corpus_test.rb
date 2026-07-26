# ©AngelaMos | 2026
# corpus_test.rb

require_relative "test_helper"
require_relative "support/adversarial_corpus"

module Rube
  class CorpusTest < Minitest::Test
    def detector
      Marshal::BoundaryDetector.new
    end

    def test_corpus_covers_both_verdicts
      verdicts = AdversarialCorpus::CASES.map { |c| c[:verdict] }.uniq
      assert_includes verdicts, AdversarialCorpus::VERDICT_ACCEPT
      assert_includes verdicts, AdversarialCorpus::VERDICT_REJECT
    end

    def test_corpus_case_names_are_unique
      names = AdversarialCorpus::CASES.map { |c| c[:name] }
      assert_equal names.length, names.uniq.length
    end

    def test_every_corpus_case_matches_its_verdict
      disagreements = AdversarialCorpus::CASES.filter_map do |kase|
        decision = detector.inspect_stream(kase[:bytes])
        expected = kase[:verdict] == AdversarialCorpus::VERDICT_ACCEPT
        next if decision.accepted? == expected

        "#{kase[:name]}: expected #{kase[:verdict]}, got #{decision.accepted? ? 'accept' : 'reject'} (#{decision.reason})"
      end

      assert_empty disagreements, "corpus disagreements:\n  #{disagreements.join("\n  ")}"
    end

    def test_parser_never_raises_outside_the_stream_error_hierarchy
      leaks = AdversarialCorpus::CASES.filter_map do |kase|
        detector.inspect_stream(kase[:bytes])
        nil
      rescue StandardError => e
        "#{kase[:name]}: #{e.class}"
      end

      assert_empty leaks, "unhandled exceptions escaped the detector:\n  #{leaks.join("\n  ")}"
    end
  end
end
