# ©AngelaMos | 2026
# adversarial_corpus.rb

module Rube
  module AdversarialCorpus
    HEADER = "\x04\x08"
    INLINE_OFFSET = 5
    INLINE_CEILING = 122
    INLINE_FLOOR = -123
    BYTE_MODULUS = 256

    VERDICT_ACCEPT = :accept
    VERDICT_REJECT = :reject

    module_function

    def fixnum(value)
      return "\x00".b if value.zero?
      return (value + INLINE_OFFSET).chr if value.positive? && value <= INLINE_CEILING
      return (value - INLINE_OFFSET + BYTE_MODULUS).chr if value.negative? && value >= INLINE_FLOOR

      wide(value)
    end

    def wide(value)
      width = 1
      width += 1 while value >= (1 << (8 * width)) || value < -(1 << (8 * width))
      stored = value.negative? ? value + (1 << (8 * width)) : value
      bytes = (0...width).map { |index| (stored >> (8 * index)) & 0xFF }
      marker = value.negative? ? BYTE_MODULUS - width : width
      (marker.chr + bytes.map(&:chr).join).b
    end

    def sym(name)
      ":#{fixnum(name.bytesize)}#{name}".b
    end

    def str(text)
      "\"#{fixnum(text.bytesize)}#{text}".b
    end

    def stream(body)
      "#{HEADER}#{body}".b
    end

    def entry(name, bytes, verdict, rationale)
      { name: name, bytes: bytes.b, verdict: verdict, rationale: rationale }.freeze
    end

    NESTED_DEPTH = 80
    WIDE_COUNT = 4_096
    MANY_SYMBOLS = 400
    HUGE_SCALAR = 300_000

    CASES = [
      entry(:nil_literal, stream("0"), VERDICT_ACCEPT,
            "the smallest legal stream"),
      entry(:boolean_true, stream("T"), VERDICT_ACCEPT,
            "primitive tag carrying no class reference"),
      entry(:fixnum_zero, stream("i\x00"), VERDICT_ACCEPT,
            "zero uses the dedicated single-byte encoding"),
      entry(:fixnum_inline_max, stream("i#{fixnum(122)}"), VERDICT_ACCEPT,
            "largest value expressible without a width prefix"),
      entry(:fixnum_wide_positive, stream("i#{fixnum(65_536)}"), VERDICT_ACCEPT,
            "three-byte little-endian encoding"),
      entry(:fixnum_wide_negative, stream("i#{fixnum(-65_536)}"), VERDICT_ACCEPT,
            "negative widths sign-extend rather than being malformed"),
      entry(:bare_symbol, stream(sym("marshal_load")), VERDICT_ACCEPT,
            "a symbol naming a sink is not itself a sink"),
      entry(:empty_array, stream("[\x00"), VERDICT_ACCEPT,
            "zero-length collection"),
      entry(:nested_arrays, stream("[\x06[\x06[\x060"), VERDICT_ACCEPT,
            "ordinary nesting well inside the depth ceiling"),
      entry(:empty_hash, stream("{\x00"), VERDICT_ACCEPT,
            "zero-entry hash"),
      entry(:shared_reference, stream("[\x07#{str('shared')}@\x06"), VERDICT_ACCEPT,
            "a legitimate object link to a previously registered string"),
      entry(:self_referential_array, stream("[\x06@\x00"), VERDICT_ACCEPT,
            "zero-indexed cycle, the shape Ruby itself emits"),
      entry(:symlink_reuse, stream("[\x07#{sym('same')};\x00"), VERDICT_ACCEPT,
            "second occurrence of a symbol is a symlink"),

      entry(:empty_stream, "", VERDICT_REJECT,
            "no header at all"),
      entry(:header_only, HEADER, VERDICT_REJECT,
            "header with no value follows"),
      entry(:wrong_major_version, "\x05\x080", VERDICT_REJECT,
            "major version has never been anything but 4"),
      entry(:future_minor_version, "\x04\x090", VERDICT_REJECT,
            "a minor above 8 is a format this parser has not seen"),
      entry(:unknown_tag, stream("\x00"), VERDICT_REJECT,
            "byte zero is not a type tag"),
      entry(:trailing_bytes, stream("0junk"), VERDICT_REJECT,
            "unread bytes after the root value indicate a smuggled second stream"),
      entry(:negative_array_count, stream("[\xFA"), VERDICT_REJECT,
            "a negative count silently yields an empty collection instead of failing"),
      entry(:negative_hash_count, stream("{\xFA"), VERDICT_REJECT,
            "same confusion in hash position"),
      entry(:negative_ivar_count, stream("I#{str('a')}\xFA"), VERDICT_REJECT,
            "negative instance variable count"),
      entry(:negative_struct_count, stream("S#{sym('A')}\xFA"), VERDICT_REJECT,
            "negative struct member count"),
      entry(:negative_bignum_words, stream("l+\xFA"), VERDICT_REJECT,
            "negative word count previously leaked a raw NoMethodError"),
      entry(:negative_string_length, stream("\"\xFA"), VERDICT_REJECT,
            "a negative length rewinds the cursor, which is a loop primitive"),
      entry(:out_of_range_object_link, stream("[\x06@\x63"), VERDICT_REJECT,
            "link index beyond the object table"),
      entry(:negative_object_link, stream("[\x06@\xFA"), VERDICT_REJECT,
            "negative index would count backwards from the end of the table"),
      entry(:negative_symlink, stream("[\x07#{sym('a')};\xFA"), VERDICT_REJECT,
            "negative symbol index"),
      entry(:truncated_string_body, stream("\"\x0aab"), VERDICT_REJECT,
            "declared length exceeds the bytes present"),
      entry(:truncated_array_elements, stream("[\x08i\x06"), VERDICT_REJECT,
            "declares three elements and supplies one"),
      entry(:truncated_multibyte_fixnum, stream("i\x03\x01"), VERDICT_REJECT,
            "declares a three-byte integer and supplies one byte"),
      entry(:deep_nesting, stream(("[\x06" * NESTED_DEPTH) + "0"), VERDICT_REJECT,
            "nesting past the boundary depth ceiling"),
      entry(:wide_collection, stream("[#{fixnum(WIDE_COUNT)}#{'0' * WIDE_COUNT}"), VERDICT_REJECT,
            "one collection consuming the whole node budget"),
      entry(:many_symbols, stream("[#{fixnum(MANY_SYMBOLS)}#{(0...MANY_SYMBOLS).map { |i| sym("s#{i}") }.join}"),
            VERDICT_REJECT,
            "attacker-chosen symbol creation past the definition ceiling"),
      entry(:huge_scalar, stream(str("A" * HUGE_SCALAR)), VERDICT_REJECT,
            "single scalar past the per-scalar byte ceiling"),
      entry(:userdef_sink, stream("u#{sym('Evil')}#{fixnum(1)}x"), VERDICT_REJECT,
            "_load runs during deserialization before any allowlist can act"),
      entry(:usermarshal_sink, stream("U#{sym('Evil')}0"), VERDICT_REJECT,
            "marshal_load runs during deserialization"),
      entry(:data_sink, stream("d#{sym('Evil')}0"), VERDICT_REJECT,
            "_load_data runs during deserialization"),
      entry(:sink_in_ivar_name_position, stream("I#{str('a')}\x06u#{sym('Evil')}#{fixnum(1)}x0"),
            VERDICT_REJECT,
            "a sink hidden where a symbol is expected must not disappear from the report"),
      entry(:plain_object_no_sink, stream("o#{sym('ERB')}\x06#{sym('@src')}#{str('payload')}"),
            VERDICT_REJECT,
            "carries no sink tag at all, which is exactly why sink detection is insufficient")
    ].freeze
  end
end
