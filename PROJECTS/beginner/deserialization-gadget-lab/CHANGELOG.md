# Changelog

All notable changes to rube are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Marshal stream parser that extracts structure, class names, and gadget sinks
  from a serialized payload without ever calling `Marshal.load`
- Sink classification along the gated/ungated dispatch axis: `marshal_load` and
  `_load` are reached through a `respond_to?` check, while `hash`, `eql?`, `<=>`
  and `[]=` are dispatched blind
- Stream validation rejecting truncated payloads, unsupported version bytes,
  unknown type tags, out-of-bounds object links and symlinks, oversized fixnum
  widths, trailing bytes, and nesting beyond a configurable depth limit
- Reflection-based gadget scanner that walks `ObjectSpace` for auto-invoked
  methods and reports whether a Prism-backed reachability filter considers each
  one reachable from a deserialized object
- Version-compatibility matrix probing six pinned Ruby images, indexed by
  RubyGems version rather than Ruby version because the gadget lives in RubyGems
- Version-scoped payload chains carrying their own affected ranges, with
  CVE-2026-41316 (ERB `@_init`) as the reference chain
- Deliberately vulnerable Sinatra target with one endpoint that loads a session
  cookie directly and one that inspects the stream first
- `BoundaryDetector` with three policies, a frozen accepted snapshot, and a
  written `LIMITATION_NOTICE` naming a bypass it cannot catch
- Detection of objects placed in **hash key** position, where `#hash` and `#eql?`
  are dispatched during load before any allowlist can act. Scoped to keys whose
  reconstructed value is not a `T_STRING`, matching what `Marshal.load` actually
  dispatches

### Changed

- `Parser.new` now enforces `Limits.new` by default instead of resolving to an
  unbounded configuration. Pass `limits: Limits.permissive` for forensic parsing
  of a stream you already trust
- `Limits.permissive` is a class method; it was an instance method that ignored
  its receiver and allocated twice

### Fixed

- `TAG_IVAR` did not increment depth, so an `I`-chain of any length parsed under
  any ceiling and a 13 KB payload exhausted the Ruby stack with a
  `SystemStackError` that no `rescue StreamError` could catch
- `read_userdef` hard-coded a depth of 1 for its class-name slot, handing that
  subtree a fresh depth budget mid-stream
- Bignum magnitude bytes bypassed the scalar budget entirely, so 400,000 of them
  were accepted where a 400,000-byte string was rejected
- Bignum sign byte was treated as negative-or-positive with no validation, so any
  byte other than `-` read as positive where `Marshal.load` raises `ArgumentError`
- Symbol references, symbol name bytes, class name bytes, instance variable
  counts, and struct member counts were charged to no budget or to an overly
  generous shared one
