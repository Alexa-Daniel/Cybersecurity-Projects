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
- `BoundaryDetector` with three policies, a frozen snapshot on any decision that
  is not blocked, and a written `LIMITATION_NOTICE` naming a bypass it cannot
  catch
- `Decision` reports exactly one of three states — `proceed?`, `blocked?`,
  `observed?` — validated in the constructor so they cannot overlap. `proceed?`
  is the only predicate that should gate a `Marshal.load`; `observed?` is the
  non-blocking observe-and-log outcome and a caller opts into it by name. There
  is no `accepted?`, because one predicate cannot answer both "did the policy
  permit this" and "is this stream free of violations"
- Scanner error accounting: every swallowed rescue is recorded with its site,
  subject and error class, and `Report` exposes `suppressed_count`,
  `suppressions_by_site`, `complete?` and `candidates_lost?`
- Packaging gate that builds the gem from its declared manifest alone, audits
  what shipped, installs the artifact on the floor and current images, and
  exercises it from the installed copy rather than the worktree. It asserts every
  shipped `lib` file is byte-identical to source, which catches an artifact built
  from stale code even though such a gem installs and requires without error. It
  can be pointed at a `.gem` you already have, and it carries three negative
  controls: a gem that ships the vulnerable target must be rejected, a gem with a
  drifted `lib` file must be rejected, and RubyGems must refuse to install below
  the declared floor
- Four-state reachability analysis. A method is analysed (touches state or does
  not), `unreadable_source?` (a path was given and could not be parsed, so it
  fails open and stays reachable), or `unanalysable?` (no Ruby source exists at
  all, so it is reported rather than guessed at). `Report#unanalysable` and
  `#fully_analysed?` state the filter's real coverage instead of implying it saw
  everything
- Reject reasons escape and bound every attacker-controlled class name before it
  reaches a caller-supplied reporter, so a name carrying CR, LF, ESC or NUL can
  no longer forge log lines

- Float bodies decode to the same value `Marshal.load` produces, including
  `inf`, `-inf` and `nan`, hex literals, and the prefix-and-stop behaviour that
  makes `"1_0"` parse as 1.0 and `"abc"` as 0.0. A body carrying Ruby's legacy
  binary mantissa is reported through `Node#undecoded_tail` rather than guessed
  at, so `fully_decoded?` is false instead of a plausible wrong number
- The parse graph is sealed before it is returned. Every node, its collections
  and its scalar values are frozen, so a caller cannot rewrite a verdict field
  or splice a node into a graph the parser already reported on

### Fixed

- `read_float` returned `nil` for seven classes of body that `Marshal.load`
  accepts, including the `inf`/`-inf`/`nan` forms Ruby emits today
- Bounds checks on symlink and object-link indices relied on negative-index
  wraparound being caught by a second clause; they now say what they mean
- `Constants::GATED_SINK_TAGS` omitted `TAG_DATA` while `Scanner::GATED_METHODS`
  listed `_load_data`, so the two halves disagreed about which sinks are gated.
  `Marshal.load` does check `respond_to?(:_load_data)` before dispatching, which
  a hand-built `d` stream naming a real C-level `T_DATA` demonstrates directly
- The defended target endpoint returned HTTP 500 with a source snippet for any
  root the detector accepted that was not a session hash
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
- `required_ruby_version` raised from `>= 3.3` to `>= 3.4`. The old floor was
  never tested: every gate stage ran on Ruby 4.0 images only. Ruby 3.3 turns out
  to fail the suite, because `Marshal.load` did not validate the bignum sign byte
  until 3.4 and the parser is written against the version that does. 3.4 is the
  oldest release on which the whole suite is green, so it is the floor.
  `TargetRubyVersion` moves with it, as those two must stay equal
- `just build` writes to `tmp/build` as the invoking user instead of dropping a
  root-owned `.gem` in the repository root, and stages only the files the gemspec
  declares, so a manifest that omits a file can no longer produce a gem that
  builds anyway

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
