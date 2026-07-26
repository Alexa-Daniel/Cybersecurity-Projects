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
